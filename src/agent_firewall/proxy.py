"""OpenAI-compatible proxy: routes each request, then reviews the tool calls in the reply.

Only `/v1/chat/completions` exists. Other API shapes get a 404 rather than an
unreviewed pass-through.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .config import Settings
from .policy import classify, inspectable_text, preview, review_tool_call
from .store import Store

UPSTREAM_TIMEOUT_SECONDS = 300.0
SESSION_HEADER = "x-afw-session"
# Request fields the firewall understands. A request using any other is kept off the cloud.
REQUEST_FIELDS = {
    "model", "messages", "tools", "tool_choice", "parallel_tool_calls", "stream", "stream_options",
    "temperature", "top_p", "n", "stop", "max_tokens", "max_completion_tokens", "presence_penalty",
    "frequency_penalty", "logit_bias", "logprobs", "top_logprobs", "seed", "user", "metadata",
    "response_format", "functions", "function_call", "store", "service_tier", "reasoning_effort",
    "modalities", "audio", "prediction",
}
REQUEST_MESSAGE_FIELDS = {
    "role", "content", "name", "tool_calls", "tool_call_id", "function_call", "refusal", "audio",
    "reasoning", "reasoning_content",
}
REQUEST_TEXT_PART_FIELDS = {"type", "text", "cache_control"}
# Fields that describe tools rather than hold conversation data.
REQUEST_SCHEMA_FIELDS = {"tools", "tool_choice", "response_format", "functions"}

# Reply fields that reach the agent. Anything else could carry an action nobody reviewed.
REPLY_FIELDS = {"id", "object", "created", "model", "choices", "usage", "system_fingerprint", "service_tier"}
REPLY_CHOICE_FIELDS = {"index", "message", "finish_reason"}
REPLY_MESSAGE_FIELDS = {"role", "content", "tool_calls", "refusal"}
REPLY_TEXT_FIELDS = ("role", "content", "refusal")
REPLY_CALL_FIELDS = {"id", "type", "function"}
REPLY_FUNCTION_FIELDS = {"name", "arguments"}
# Field names outside the reviewed shape that signal an attempted action rather than metadata.
REPLY_ACTION_FIELDS = {"tool_calls", "function_call", "delta", "message", "output", "tool_use"}


def _message_is_opaque(message: Any) -> bool:
    if not isinstance(message, dict) or set(message) - REQUEST_MESSAGE_FIELDS:
        return True
    content = message.get("content")
    if isinstance(content, list):
        return not all(
            isinstance(part, dict)
            and part.get("type") in ("text", "input_text")
            and isinstance(part.get("text"), str)
            and not set(part) - REQUEST_TEXT_PART_FIELDS
            for part in content
        )
    return not (content is None or isinstance(content, str))


def _request_labels(body: dict, canaries: tuple[str, ...]) -> set[str]:
    """Label everything that would be forwarded, so no field is both unscanned and sent."""
    schemas = [value for key, value in body.items() if key in REQUEST_SCHEMA_FIELDS]
    conversation = {key: value for key, value in body.items() if key not in REQUEST_SCHEMA_FIELDS}
    labels = classify("\n".join(inspectable_text(conversation)), canaries)
    labels |= classify("\n".join(inspectable_text(schemas)), canaries, exact_only=True)
    if set(body) - REQUEST_FIELDS or any(_message_is_opaque(m) for m in body["messages"]):
        labels.add("opaque")
    return labels


def _request_hash(session: str, name: str, raw_arguments: str) -> str:
    payload = json.dumps(
        {"session": session, "name": name, "arguments": raw_arguments},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _strip_unreviewed(container: dict, allowed: set[str]) -> bool:
    """Drop every field outside `allowed`; True when a dropped one was carrying an action."""
    carried_action = False
    for key in set(container) - allowed:
        carried_action |= key in REPLY_ACTION_FIELDS and bool(container[key])
        del container[key]
    return carried_action


def _reviewed_call(call: dict) -> dict:
    """Reduce an approved tool call to the fields its review covered."""
    kept = {key: value for key, value in call.items() if key in REPLY_CALL_FIELDS}
    kept["function"] = {
        key: value for key, value in call["function"].items() if key in REPLY_FUNCTION_FIELDS
    }
    return kept


def _as_sse(data: dict) -> StreamingResponse:
    """Replay a finished completion as SSE: tool calls cannot be reviewed mid-stream."""

    def chunk(choices: list[dict]) -> str:
        return "data: " + json.dumps({
            "id": data.get("id", "afw"), "object": "chat.completion.chunk",
            "created": data.get("created", 0), "model": data.get("model", ""),
            "choices": choices,
        }) + "\n\n"

    def body():
        for choice in data.get("choices", []):
            message = choice.get("message") or {}
            delta: dict[str, Any] = {"role": "assistant", "content": message.get("content") or ""}
            if message.get("refusal"):
                delta["refusal"] = message["refusal"]
            if message.get("tool_calls"):
                delta["tool_calls"] = [
                    {**call, "index": i} for i, call in enumerate(message["tool_calls"])
                ]
            index = choice.get("index", 0)
            yield chunk([{"index": index, "delta": delta, "finish_reason": None}])
            yield chunk([{"index": index, "delta": {}, "finish_reason": choice.get("finish_reason")}])
        yield "data: [DONE]\n\n"

    return StreamingResponse(body(), media_type="text/event-stream")


def create_proxy_app(
    settings: Settings, store: Store, transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    app = FastAPI(title="Agent Firewall proxy")
    client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_SECONDS, transport=transport)

    async def call_upstream(route: str, body: dict) -> httpx.Response:
        is_cloud = route == "cloud"
        base_url = settings.cloud_base_url if is_cloud else settings.local_base_url
        model = (settings.cloud_model if is_cloud else settings.local_model) or body.get("model")
        payload = {**body, "model": model, "stream": False}
        # The legacy function-calling parameters would invite replies outside the tool_calls review.
        for key in ("stream_options", "functions", "function_call"):
            payload.pop(key, None)
        headers = {}
        if is_cloud and settings.cloud_api_key:
            headers["Authorization"] = f"Bearer {settings.cloud_api_key}"
        return await client.post(f"{base_url}/chat/completions", json=payload, headers=headers)

    async def review_call(session: str, call: dict, agent_says: str) -> str | None:
        """Return None to keep the tool call, or a human-readable reason it was stopped."""
        function = call.get("function") if isinstance(call, dict) else None
        is_function = isinstance(call, dict) and call.get("type", "function") == "function"
        if not is_function or not isinstance(function, dict) or not isinstance(function.get("name"), str):
            store.record("tool", session=session, decision="block", why="malformed")
            store.counters["tool_block"] += 1
            return "a malformed action"

        name = function["name"]
        raw_arguments = function.get("arguments") or ""
        if not isinstance(raw_arguments, str):
            raw_arguments = json.dumps(raw_arguments)
        sha256 = _request_hash(session, name, raw_arguments)
        verdict = review_tool_call(name, raw_arguments, store.session_labels[session], settings)
        store.counters[f"tool_{verdict.decision}"] += 1
        store.record("tool", session=session, tool=name, decision=verdict.decision, sha256=sha256)

        if verdict.decision == "allow":
            return None
        if verdict.decision == "block":
            return verdict.title

        facts = list(verdict.facts)
        if agent_says:
            facts.append(("Agent says", preview(agent_says)))
        approval = store.create_approval(
            session, name, verdict.title, facts, verdict.reasons, sha256
        )
        status = await store.wait(approval)
        store.counters[f"approval_{status}"] += 1
        store.record("approval", session=session, tool=name, status=status, sha256=sha256)
        return None if status == "approved" else f"{verdict.title} ({status})"

    def record_block(session: str, why: str) -> None:
        store.record("tool", session=session, decision="block", why=why)
        store.counters["tool_block"] += 1

    async def review_reply(data: dict, session: str) -> None:
        """Reduce `data` in place to the shape the review covers, then review what is left."""
        unreviewed_at_top = _strip_unreviewed(data, REPLY_FIELDS)
        choices = data.get("choices")
        choices = [c for c in choices if isinstance(c, dict)] if isinstance(choices, list) else []
        if unreviewed_at_top and not choices:
            choices = [{"index": 0, "finish_reason": "stop"}]
        data["choices"] = choices

        for position, choice in enumerate(choices):
            stopped: list[str] = []
            misplaced = _strip_unreviewed(choice, REPLY_CHOICE_FIELDS) or (unreviewed_at_top and position == 0)
            message = choice.get("message")
            if not isinstance(message, dict):
                misplaced = misplaced or bool(message)
                message = choice["message"] = {"role": "assistant", "content": None}
            misplaced = _strip_unreviewed(message, REPLY_MESSAGE_FIELDS) or misplaced
            if misplaced:
                record_block(session, "misplaced_action")
                stopped.append("an action in an unsupported format")

            unreadable = [k for k in REPLY_TEXT_FIELDS if not isinstance(message.get(k), (str, type(None)))]
            if unreadable:
                for key in unreadable:
                    del message[key]
                message.setdefault("role", "assistant")
                record_block(session, "non_text_reply")
                stopped.append("a reply the firewall could not read")

            calls = message.get("tool_calls")
            if calls and not isinstance(calls, list):
                calls = [calls]
            if calls:
                outcomes = await asyncio.gather(
                    *(review_call(session, call, message.get("content") or "") for call in calls)
                )
                kept = [_reviewed_call(call) for call, reason in zip(calls, outcomes) if reason is None]
                stopped += [reason for reason in outcomes if reason is not None]
                if kept:
                    message["tool_calls"] = kept
                else:
                    message.pop("tool_calls", None)
            if stopped and not message.get("tool_calls"):
                choice["finish_reason"] = "stop"
            if stopped:
                notice = "Agent Firewall stopped: " + "; ".join(stopped) + ". Do not retry this action."
                message["content"] = "\n".join(filter(None, [message.get("content"), notice]))

    @app.get("/v1/models")
    async def models() -> dict:
        names = [m for m in (settings.local_model, settings.cloud_model) if m] or ["agent-firewall"]
        return {"object": "list", "data": [{"id": name, "object": "model"} for name in names]}

    @app.post("/v1/chat/completions")
    async def completions(request: Request):
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": {"message": "invalid JSON"}}, status_code=400)
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            return JSONResponse({"error": {"message": "messages required"}}, status_code=400)

        session = request.headers.get(SESSION_HEADER, "default")
        labels = _request_labels(body, settings.canaries)
        session_labels = store.add_labels(session, labels)

        if session_labels:
            route, why = "local", "protected: " + ",".join(sorted(session_labels))
        elif settings.cloud_base_url:
            route, why = "cloud", "no protected data"
        else:
            route, why = "local", "no cloud configured"

        try:
            upstream = await call_upstream(route, body)
        except httpx.TransportError:
            if route == "cloud":
                route, why = "local", "cloud unreachable"
                try:
                    upstream = await call_upstream(route, body)
                except httpx.TransportError:
                    upstream = None
            else:
                # Protected data has no other legal destination, so the cloud is never tried.
                upstream = None
        store.counters[f"route_{route}"] += 1
        store.record("route", session=session, route=route, why=why, labels=sorted(session_labels))
        if upstream is None:
            return JSONResponse(
                {"error": {"message": "local model unavailable"}}, status_code=503,
                headers={"x-afw-route": route},
            )
        if upstream.status_code != 200:
            return JSONResponse(
                {"error": {"message": f"upstream returned {upstream.status_code}"}},
                status_code=upstream.status_code, headers={"x-afw-route": route},
            )

        data = upstream.json()
        await review_reply(data, session)
        if body.get("stream"):
            return _as_sse(data)
        return JSONResponse(data, headers={"x-afw-route": route})

    return app
