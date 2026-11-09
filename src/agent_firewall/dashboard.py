"""Groups recorded activity and scan results into the dashboard's categories."""

from __future__ import annotations

import json
import os
from collections import Counter, deque
from collections.abc import Collection

from .config import Settings
from .custom_policy import PolicyBook

CATEGORIES = ("denied", "sensitive", "uncertain", "local", "cloud")
MAX_AUDIT_LINES = 20_000
MAX_RETURNED_ITEMS = 1_000
_SENSITIVE_LABELS = {"financial", "health", "identity", "canary", "credentials", "inferred"}
_UNSURE_REASONS = ("can't tell", "doesn't recognize", "fields the firewall")
_CLOUD_AGENTS = {"claude-code"}
_TOOLS_RETURNING_DATA = {"Read", "Grep", "Bash", "WebFetch", "WebSearch"}


def read_audit(path: str) -> list[dict]:
    try:
        with open(path, encoding="utf-8") as handle:
            lines = deque(handle, maxlen=MAX_AUDIT_LINES)
    except OSError:
        return []
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _is_unsure(labels: set[str], reasons: list[str]) -> bool:
    return "opaque" in labels or any(marker in reason for reason in reasons for marker in _UNSURE_REASONS)


def _item(event: dict, state: str, categories: set[str], labels: set[str], reasons: list[str]) -> dict:
    if labels & _SENSITIVE_LABELS:
        categories = categories | {"sensitive"}
    if _is_unsure(labels, reasons):
        categories = categories | {"uncertain"}
    return {
        "ts": event.get("ts", 0), "agent": event.get("agent", "agent"), "tool": event.get("tool", ""),
        "target": event.get("target") or event.get("why") or "", "state": state,
        "labels": sorted(labels), "reasons": reasons, "categories": sorted(categories),
    }


def _strings(value: object) -> list[str]:
    """Read a list field from the log, which may hold older or damaged lines."""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _asks_answered_by_approvals(events: list[dict]) -> set[int]:
    """Pair each approval with the earliest open ask, since identical actions share a hash."""
    open_asks: dict[object, deque[int]] = {}
    answered: set[int] = set()
    for position, event in enumerate(events):
        key = event.get("sha256")
        if event.get("kind") == "tool" and event.get("decision") == "ask":
            open_asks.setdefault(key, deque()).append(position)
        elif event.get("kind") == "approval" and open_asks.get(key):
            answered.add(open_asks[key].popleft())
    return answered


def _activity_items(events: list[dict], waiting: Collection[str]) -> list[dict]:
    answered = _asks_answered_by_approvals(events)
    asked = {e.get("sha256"): e for e in events if e.get("kind") == "tool" and e.get("decision") == "ask"}
    items = []
    for position, event in enumerate(events):
        kind = event.get("kind")
        labels = set(_strings(event.get("labels")))
        reasons = _strings(event.get("reasons"))
        returns_data = event.get("agent") in _CLOUD_AGENTS and event.get("tool") in _TOOLS_RETURNING_DATA
        if kind == "route":
            route = event.get("route")
            if route in ("local", "cloud"):
                routed = {**event, "tool": "model"}
                items.append(_item(routed, route, {route}, labels, reasons))
        elif kind == "tool":
            decision = event.get("decision")
            if decision == "ask" and position in answered:
                continue
            state = str(decision)
            if decision == "ask" and event.get("sha256") not in waiting:
                state = "unanswered"
            if decision == "block":
                categories = {"denied"}
            elif decision == "allow" and returns_data:
                categories = {"cloud"}
            else:
                categories = set()
            items.append(_item(event, state, categories, labels, reasons))
        elif kind == "approval":
            status = event.get("status")
            origin = asked.get(event.get("sha256"), {})
            labels |= set(_strings(origin.get("labels")))
            reasons = reasons or _strings(origin.get("reasons"))
            if status in ("denied", "expired"):
                categories = {"denied"}
            elif status == "kept_local":
                categories = {"local"}
            elif status == "approved" and returns_data:
                categories = {"cloud"}
            else:
                categories = set()
            items.append(_item(event, str(status), categories, labels, reasons))
    return items


def _file_items(files: list[tuple[str, list[str], str, float]]) -> list[dict]:
    home = os.path.expanduser("~")
    items = []
    for path, labels, method, scanned_at in files:
        shown = "~" + path[len(home):] if path.startswith(home + os.sep) else path
        event = {"ts": scanned_at, "agent": "scanner", "tool": method, "target": shown}
        items.append(_item(event, "file", set(), set(labels), []))
    return items


def all_items(
    settings: Settings, files: list[tuple[str, list[str], str, float]], waiting: Collection[str] = (),
) -> list[dict]:
    combined = _activity_items(read_audit(settings.audit_path), waiting) + _file_items(files)
    combined.sort(key=lambda item: item["ts"], reverse=True)
    return combined


def category_counts(items: list[dict]) -> dict[str, int]:
    counts = Counter(category for item in items for category in item["categories"])
    return {category: counts.get(category, 0) for category in CATEGORIES} | {"all": len(items)}


def select_items(items: list[dict], category: str, query: str) -> dict:
    needle = query.casefold().strip()
    matched = [
        item for item in items
        if (category == "all" or category in item["categories"])
        and (not needle or needle in f"{item['target']} {item['tool']} {item['agent']}".casefold())
    ]
    return {"total": len(matched), "items": matched[:MAX_RETURNED_ITEMS]}


BUILT_IN_RULES = [
    {
        "title": "Blocked with no popup",
        "rules": [
            "A planted bait secret appears in an action",
            "An action can't be parsed, repeats a field, or is too long to show in full",
        ],
    },
    {
        "title": "Always asks you",
        "rules": [
            "Moving money, paying, adding a payee, or trading",
            "Changing or sharing a health record",
            "Claude Code: reading a file detected as financial, health or identity data",
            "Claude Code: searching a folder that holds sensitive files",
            "Reading password or key files",
            "Files or commands the firewall can't understand",
            "Contacting a website not on your allowed list",
            "Emailing a new recipient",
            "Deleting files",
            "Changing settings that can run code or turn off the firewall",
            "Changing a file outside the project",
            "Using a tool the firewall doesn't recognize",
        ],
    },
    {
        "title": "Allowed and logged",
        "rules": [
            "Claude Code: reading or searching files with nothing sensitive detected",
            "Other agents: reading ordinary paths, after which any sensitive data keeps that session on the local model",
            "Simple read-only commands such as ls and pwd",
            "Claude Code: changing ordinary files inside the project",
        ],
    },
]


def policy_view(settings: Settings, book: PolicyBook) -> dict:
    return {
        "built_in": BUILT_IN_RULES,
        "entries": book.entries,
        "settings": {
            "approval_timeout_seconds": int(settings.approval_timeout_seconds),
            "allowed_hosts": list(settings.allowed_hosts),
            "known_recipients": list(settings.known_recipients),
            "bait_secrets": len(settings.canaries),
            "scan_roots": list(settings.scan_roots),
            "proxy_cloud_configured": bool(settings.cloud_base_url),
            "local_model": settings.local_model,
            "worst_case_model": settings.worst_case_model,
        },
    }
