"""Ideas and rules the user types into the dashboard.

Rules can only make the firewall stricter. There is deliberately no "allow" kind: the
page that edits them is reachable by anything holding its token, and a typed rule must
never be a way to switch a protection off.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path

from .policy import Verdict, _folded, display, inspectable_text

KINDS = ("idea", "ask", "block")
MAX_ENTRIES = 300
MAX_TEXT_CHARS = 500
MIN_RULE_CHARS = 2
# Default-ignorable characters that aren't Cc or Cf, so `_folded` would leave them in place.
_INVISIBLE = re.compile("[\u034f\u17b4\u17b5\u180b-\u180f\u2065\ufe00-\ufe0f\ufff0-\ufff8\U000e0000-\U000e0fff]")
_BLANK_FILLERS = re.compile("[\u115f\u1160\u2800\u3164\uffa0]")


def searchable_text(*parts: object) -> str:
    """Join decoded text so a rule can't be dodged by JSON escapes such as `\\u002e` for a dot."""
    return " ".join(piece for part in parts for piece in inspectable_text(part))


def _forms(text: str) -> tuple[str, str]:
    """Return `text` with gaps kept as spaces, and with control characters simply deleted.

    Both are needed: "git\\tpush" is two words to a shell, but "pay\\tpal.com" is one
    hostname to a URL parser, because URL parsers discard tabs and newlines.
    """
    cleaned = _INVISIBLE.sub("", _BLANK_FILLERS.sub(" ", text)).replace("\\\n", " ")
    spaced = " ".join(_folded(" ".join(cleaned.split())).split())
    return spaced, " ".join(_folded(cleaned).split())


class PolicyBook:
    """Must be used from one event loop. An empty path keeps entries in memory only."""

    def __init__(self, path: str = ""):
        self._path = Path(path).expanduser() if path else None
        self.entries: list[dict] = self._load()

    def _load(self) -> list[dict]:
        if self._path is None or not self._path.exists():
            return []
        try:
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # Kept for recovery: overwriting it would silently lose the user's rules.
            self._path.replace(self._path.with_suffix(".corrupt"))
            return []
        return [e for e in loaded if isinstance(e, dict) and e.get("kind") in KINDS and e.get("text")]

    def _save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle, draft = tempfile.mkstemp(dir=self._path.parent, prefix=".policy-")
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(self.entries, output, ensure_ascii=False, indent=2)
        os.replace(draft, self._path)

    def add(self, kind: str, text: str) -> dict:
        """Store an entry, raising ValueError with a message the page can show."""
        cleaned = " ".join(text.split())
        if kind not in KINDS:
            raise ValueError("unknown kind")
        if not cleaned or len(cleaned) > MAX_TEXT_CHARS:
            raise ValueError("text must be 1 to 500 characters")
        if kind != "idea" and len(cleaned) < MIN_RULE_CHARS:
            raise ValueError("a rule needs at least 2 characters")
        if len(self.entries) >= MAX_ENTRIES:
            raise ValueError("too many entries, delete some first")
        entry = {"id": secrets.token_hex(6), "kind": kind, "text": cleaned, "created": round(time.time(), 3)}
        self.entries.insert(0, entry)
        self._save()
        return entry

    def remove(self, entry_id: str) -> bool:
        kept = [entry for entry in self.entries if entry["id"] != entry_id]
        removed = len(kept) != len(self.entries)
        if removed:
            self.entries = kept
            self._save()
        return removed

    def match(self, haystack: str) -> dict | None:
        """Return the strictest rule whose text appears in `haystack`."""
        forms = _forms(haystack)
        hits = [
            e for e in self.entries
            if e["kind"] != "idea" and any(_forms(e["text"])[0] in form for form in forms)
        ]
        return next((e for e in hits if e["kind"] == "block"), hits[0] if hits else None)

    def apply(self, verdict: Verdict, haystack: str, agent: str, facts: list[tuple[str, str]]) -> Verdict:
        """Tighten a verdict if a rule matches. Never loosens one."""
        rule = self.match(haystack)
        if rule is None or verdict.decision == "block":
            return verdict
        reason = f"Matches your rule: {display(rule['text'])}"
        if rule["kind"] == "block":
            return Verdict(
                # The title reaches the agent, and naming the text would show it what to rephrase.
                "block", "Blocked by one of your rules",
                verdict.facts or facts, [reason, *verdict.reasons],
            )
        if verdict.decision == "ask":
            verdict.reasons.insert(0, reason)
            # The person must be able to see the text that matched.
            shown = {label for label, _ in verdict.facts}
            verdict.facts.extend(fact for fact in facts if fact[0] not in shown)
            return verdict
        return Verdict("ask", f"{agent} wants to do something your rule covers", facts, [reason])
