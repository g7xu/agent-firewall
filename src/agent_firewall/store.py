"""In-memory session state, pending approvals, and the content-free audit log.

All methods must run on one event loop: approvals wake waiters through
`asyncio.Event`, which is not safe to set from another loop or thread.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import stat
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings

RECENT_EVENT_LIMIT = 200


@dataclass
class Approval:
    id: str
    session: str
    tool: str
    title: str
    facts: list[tuple[str, str]]
    reasons: list[str]
    sha256: str
    expires_at: float
    can_keep_local: bool = False
    worst_case: str = ""
    ai_worst_case: str = ""
    status: str = "pending"
    event: asyncio.Event = field(default_factory=asyncio.Event)


class Store:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.session_labels: dict[str, set[str]] = defaultdict(set)
        self.approvals: dict[str, Approval] = {}
        self.events: deque[dict] = deque(maxlen=RECENT_EVENT_LIMIT)
        self.counters: Counter[str] = Counter()
        if not settings.audit_path or Path(settings.audit_path).is_dir():
            raise ValueError("AUDIT_PATH must name a file")
        self._audit_path = Path(settings.audit_path)

    def add_labels(self, session: str, labels: set[str]) -> set[str]:
        """Labels only accumulate, so a paraphrase cannot launder a session."""
        self.session_labels[session] |= labels
        return set(self.session_labels[session])

    def record(self, kind: str, **fields) -> None:
        """Log an event. Callers pass names, labels and hashes rather than file or message contents."""
        event = {"ts": round(time.time(), 3), "kind": kind, **fields}
        self.events.append(event)
        descriptor = os.open(self._audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.fchmod(descriptor, 0o600)  # Also repairs a log created or loosened by something else.
        with os.fdopen(descriptor, "a") as handle:
            handle.write(json.dumps(event) + "\n")

    def create_approval(
        self, session: str, tool: str, title: str, facts: list[tuple[str, str]],
        reasons: list[str], sha256: str, can_keep_local: bool = False, worst_case: str = "",
        ai_worst_case: str = "",
    ) -> Approval:
        approval = Approval(
            id=f"apr_{secrets.token_hex(6)}",
            session=session, tool=tool, title=title, facts=facts, reasons=reasons, sha256=sha256,
            expires_at=time.time() + self.settings.approval_timeout_seconds,
            can_keep_local=can_keep_local, worst_case=worst_case, ai_worst_case=ai_worst_case,
        )
        self.approvals[approval.id] = approval
        return approval

    async def wait(self, approval: Approval) -> str:
        """Block until decided. Expiry resolves to a non-approval, so silence never approves."""
        try:
            await asyncio.wait_for(
                approval.event.wait(), timeout=self.settings.approval_timeout_seconds
            )
        except asyncio.TimeoutError:
            if approval.status == "pending":
                approval.status = "expired"
        approval.facts = []
        return approval.status

    def pending(self) -> list[Approval]:
        now = time.time()
        return [a for a in self.approvals.values() if a.status == "pending" and a.expires_at > now]

    def decide(self, approval_id: str, sha256: str, decision: str) -> str:
        """Apply a phone decision to the exact request the phone was shown.

        Returns "ok", "not_found", "hash_mismatch", "already_decided", "not_offered" or "expired".
        """
        approval = self.approvals.get(approval_id)
        if approval is None:
            return "not_found"
        if approval.sha256 != sha256:
            return "hash_mismatch"
        if approval.status != "pending":
            return "already_decided"
        if approval.expires_at <= time.time():
            approval.status = "expired"
            approval.event.set()
            return "expired"
        if decision == "keep_local" and not approval.can_keep_local:
            return "not_offered"
        approval.status = {"approve": "approved", "keep_local": "kept_local"}.get(decision, "denied")
        approval.event.set()
        return "ok"
