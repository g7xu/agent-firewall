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
from .policy import classify, display, review_tool_call
from .store import Store

UPSTREAM_TIMEOUT_SECONDS = 300.0
SESSION_HEADER = "x-afw-session"


def _scannable_text(messages: list[dict]) -> tuple[str, bool]:
    """Return all inspectable text, plus whether any part could not be inspected."""
    parts: list[str] = []
    opaque = False
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") in ("text", "input_text"):
                    parts.append(str(part.get("text", "")))
                else:
                    opaque = True
        elif content is not None:
            opaque = True
        for call in message.get("tool_calls") or []:
            parts.append(str((call.get("function") or {}).get("arguments", "")))
    return "\n".join(parts), opaque


def _request_hash(session: str, name: str, raw_arguments: str) -> str:
    payload = json.dumps(
        {"session": session, "name": name, "arguments": raw_arguments},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


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
        payload.pop("stream_options", None)
        headers = {}
        if is_cloud and settings.cloud_api_key:
            headers["Authorization"] = f"Bearer {settings.cloud_api_key}"
        return await client.post(f"{base_url}/chat/completions", json=payload, headers=headers)

    async def review_call(session: str, call: dict, agent_says: str) -> str | None:
        """Return None to keep the tool call, or a human-readable reason it was stopped."""
        function = call.get("function") if isinstance(call, dict) else None
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
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
            facts.append(("Agent says", display(agent_says)))
        approval = store.create_approval(
            session, name, verdict.title, facts, verdict.reasons, sha256
        )
        status = await store.wait(approval)
        store.counters[f"approval_{status}"] += 1
        store.record("approval", session=session, tool=name, status=status, sha256=sha256)
        return None if status == "approved" else f"{verdict.title} ({status})"

    async def review_choices(data: dict, session: str) -> None:
        for choice in data.get("choices", []):
            message = choice.get("message") or {}
            calls = message.get("tool_calls")
            if not calls:
                continue
            outcomes = await asyncio.gather(
                *(review_call(session, call, message.get("content") or "") for call in calls)
            )
            kept = [call for call, stopped in zip(calls, outcomes) if stopped is None]
            stopped = [reason for reason in outcomes if reason is not None]
            if kept:
                message["tool_calls"] = kept
            else:
                message.pop("tool_calls", None)
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
        text, opaque = _scannable_text(body["messages"])
        labels = classify(text, settings.canaries) | ({"opaque"} if opaque else set())
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
        await review_choices(data, session)
        if body.get("stream"):
            return _as_sse(data)
        return JSONResponse(data, headers={"x-afw-route": route})

    return app
