"""Approval page and live dashboard, served separately from the proxy.

This app listens on the LAN so a phone can reach it; the proxy stays on
loopback so nobody on shared Wi-Fi can spend the cloud key.
"""

from __future__ import annotations

import hmac
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import dashboard
from .config import Settings
from .custom_policy import PolicyBook
from .scanner import Scanner
from .store import Store

_STATIC = Path(__file__).parent / "static"
_LOOPBACK = {"127.0.0.1", "::1"}
_LOCAL_NAMES = {"127.0.0.1", "localhost", "[::1]"}
_ITEMS_CACHE_SECONDS = 1.0


class Decision(BaseModel):
    id: str
    sha256: str
    decision: str


class NewEntry(BaseModel):
    kind: str
    text: str


def create_phone_app(
    settings: Settings, store: Store, scanner: Scanner | None = None, policy: PolicyBook | None = None,
) -> FastAPI:
    app = FastAPI(title="Agent Firewall phone")
    book = policy or PolicyBook()

    def require_this_mac(request: Request) -> None:
        """File names and policy edits stay off the network, where this page is plain HTTP."""
        host_header = request.headers.get("host", "").rsplit(":", 1)[0]
        if request.client is None or request.client.host not in _LOOPBACK or host_header not in _LOCAL_NAMES:
            raise HTTPException(status_code=403, detail="only available on this Mac")

    cache: dict = {"built": 0.0, "items": []}

    def current_items() -> list[dict]:
        """Both polled endpoints share one build, since the page requests them together."""
        now = time.monotonic()
        if now - cache["built"] >= _ITEMS_CACHE_SECONDS:
            waiting = {approval.sha256 for approval in store.pending()}
            cache["items"] = dashboard.all_items(settings, scanner.flagged_files() if scanner else [], waiting)
            cache["built"] = now
        return cache["items"]

    def require_token(t: str = Query(default="")) -> None:
        if not settings.phone_token or not hmac.compare_digest(t, settings.phone_token):
            raise HTTPException(status_code=403, detail="bad token")

    @app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_token)])
    def approvals_page() -> str:
        return (_STATIC / "phone.html").read_text()

    @app.get("/dash", response_class=HTMLResponse, dependencies=[Depends(require_token)])
    def dashboard_page() -> str:
        return (_STATIC / "dash.html").read_text()

    @app.get("/api/pending", dependencies=[Depends(require_token)])
    def pending() -> list[dict]:
        now = time.time()
        return [
            {
                "id": a.id, "title": a.title, "facts": a.facts, "reasons": a.reasons,
                "sha256": a.sha256, "seconds_left": max(0, round(a.expires_at - now)),
                "can_keep_local": a.can_keep_local, "worst_case": a.worst_case, "ai_worst_case": a.ai_worst_case,
            }
            for a in store.pending()
        ]

    @app.post("/api/decide", dependencies=[Depends(require_token)])
    def decide(decision: Decision) -> dict:
        if decision.decision not in ("approve", "deny", "keep_local"):
            raise HTTPException(status_code=400, detail="bad decision")
        result = store.decide(decision.id, decision.sha256, decision.decision)
        if result != "ok":
            raise HTTPException(status_code=409, detail=result)
        return {"status": "ok"}

    private = [Depends(require_token), Depends(require_this_mac)]

    @app.get("/api/overview", dependencies=private)
    def overview() -> dict:
        items = current_items()
        return {
            "counts": dashboard.category_counts(items),
            "activity": sum(1 for item in items if item["agent"] != "scanner"),
            "scan": scanner.status() if scanner else None,
        }

    @app.get("/api/items", dependencies=private)
    def items(category: str = "all", q: str = "") -> dict:
        if category != "all" and category not in dashboard.CATEGORIES:
            raise HTTPException(status_code=400, detail="unknown category")
        return dashboard.select_items(current_items(), category, q)

    @app.get("/api/policy", dependencies=private)
    def read_policy() -> dict:
        return dashboard.policy_view(settings, book)

    @app.post("/api/policy/entries", dependencies=private)
    async def add_entry(entry: NewEntry) -> dict:
        try:
            return book.add(entry.kind, entry.text)
        except ValueError as problem:
            raise HTTPException(status_code=400, detail=str(problem))

    @app.delete("/api/policy/entries/{entry_id}", dependencies=private)
    async def delete_entry(entry_id: str) -> dict:
        if not book.remove(entry_id):
            raise HTTPException(status_code=404, detail="no such entry")
        return {"status": "ok"}

    @app.get("/api/stats", dependencies=private)
    def stats() -> dict:
        return {
            "counters": dict(store.counters), "events": list(store.events)[-50:][::-1],
            "scan": scanner.status() if scanner else None,
        }

    return app
