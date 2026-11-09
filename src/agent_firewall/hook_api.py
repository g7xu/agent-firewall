"""HTTP endpoint Claude Code's PreToolUse hook calls before each action.

Lives on the loopback proxy port. Claude Code must be configured with
`onFailure: block`, otherwise an unreachable firewall lets every action through.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

import httpx
from fastapi import APIRouter, Body

from .config import Settings
from .gate import Review, review_claude_code
from .local_summary import summarize
from .popup import ask_on_mac, card_text
from .store import Approval, Store

AGENT = "claude-code"
SUMMARY_TIMEOUT_SECONDS = 200.0


def _decision(permission: str, reason: str) -> dict:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": permission,
        "permissionDecisionReason": reason,
    }}


def create_hook_router(
    settings: Settings, store: Store, transport: httpx.AsyncBaseTransport | None = None
) -> APIRouter:
    router = APIRouter()
    client = httpx.AsyncClient(timeout=SUMMARY_TIMEOUT_SECONDS, transport=transport)

    async def wait_for_human(approval: Approval) -> str:
        popup = None
        if settings.popup == "mac":
            async def ask() -> None:
                text = card_text(approval.title, approval.facts, approval.reasons)
                timeout = int(settings.approval_timeout_seconds)
                decision = await ask_on_mac(text, timeout, approval.can_keep_local)
                if decision:
                    store.decide(approval.id, approval.sha256, decision)
            popup = asyncio.create_task(ask())
        try:
            return await store.wait(approval)
        finally:
            if popup:
                popup.cancel()

    async def keep_local(review: Review) -> dict:
        summary = await summarize(review.keep_local_path or "", settings, client)
        if summary is None:
            return _decision("deny", "Agent Firewall kept this file on the user's Mac and has no summary to share.")
        return _decision(
            "deny",
            "Agent Firewall kept this file on the user's Mac. Do not retry reading it. "
            f"A small on-device model summarized it, and its figures may be approximate: {summary}",
        )

    @router.post("/hook/claude-code")
    async def claude_code_hook(payload: dict = Body(...)) -> dict:
        session = f"{AGENT}:{payload.get('session_id', 'unknown')}"
        tool = str(payload.get("tool_name", ""))
        review = review_claude_code(payload, store.session_labels[session], settings)
        verdict = review.verdict
        sha256 = hashlib.sha256(
            json.dumps({"tool": tool, "input": payload.get("tool_input")}, sort_keys=True).encode()
        ).hexdigest()

        def log(decision: str, decided_by: str) -> None:
            store.counters[f"tool_{decision}"] += 1
            store.record(
                "tool", agent=AGENT, session=session, tool=tool, target=review.target,
                decision=decision, decided_by=decided_by, labels=sorted(review.labels), sha256=sha256,
            )

        if verdict.decision == "allow":
            log("allow", "rules")
            return {}  # Claude Code's own permission rules still apply.
        if verdict.decision == "block":
            log("block", "rules")
            return _decision("deny", f"Agent Firewall: {verdict.title}.")

        log("ask", "rules")
        approval = store.create_approval(
            session, tool, verdict.title, verdict.facts, verdict.reasons, sha256,
            can_keep_local=review.keep_local_path is not None,
        )
        status = await wait_for_human(approval)
        store.counters[f"approval_{status}"] += 1
        store.record(
            "approval", agent=AGENT, session=session, tool=tool, target=review.target,
            status=status, sha256=sha256,
        )
        if status == "approved":
            store.add_labels(session, review.labels)
            return _decision("allow", "Approved by the user in Agent Firewall.")
        if status == "kept_local":
            return await keep_local(review)
        return _decision("deny", f"Agent Firewall: the user did not approve this ({status}). Do not retry.")

    return router
