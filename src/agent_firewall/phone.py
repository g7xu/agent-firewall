"""Approval page and live dashboard, served separately from the proxy.

This app listens on the LAN so a phone can reach it; the proxy stays on
loopback so nobody on shared Wi-Fi can spend the cloud key.
"""

from __future__ import annotations

import hmac
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .config import Settings
from .scanner import Scanner
from .store import Store

_STATIC = Path(__file__).parent / "static"


class Decision(BaseModel):
    id: str
    sha256: str
    decision: str


def create_phone_app(settings: Settings, store: Store, scanner: Scanner | None = None) -> FastAPI:
    app = FastAPI(title="Agent Firewall phone")

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

    @app.get("/api/stats", dependencies=[Depends(require_token)])
    def stats() -> dict:
        return {
            "counters": dict(store.counters), "events": list(store.events)[-50:][::-1],
            "scan": scanner.status() if scanner else None,
        }

    return app
