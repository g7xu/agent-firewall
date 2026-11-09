"""Deterministic data labeling and tool-call review.

Everything here is plain code on purpose: model output and tool results are
attacker-influenced, so no decision in this module may depend on a model.
Tools the policy has never heard of are held for a human, never allowed.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from .config import Settings

_PATTERNS = {
    "financial": [
        re.compile(p, re.I)
        for p in (
            r"\bACCT-\d{6,}\b",
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\baccount (?:number|no\.?)\b",
            r"\brouting (?:number|no\.?)\b",
            r"\bstatement balance\b",
            r"\bIBAN\b",
        )
    ],
    "health": [
        re.compile(p, re.I)
        for p in (
            r"\bMRN-?\d{5,}\b",
            r"\bdiagnos(?:is|ed)\b",
            r"\bprescri(?:ption|bed)\b",
            r"\blab results?\b",
            r"\bpatient note\b",
            r"\bA1C\b",
        )
    ],
}
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

MONEY_TOOLS = {
    "transfer_money", "send_payment", "create_refund", "create_payout",
    "add_payee", "change_bank_details", "place_trade",
}
HEALTH_WRITE_TOOLS = {
    "update_prescription", "share_record", "message_clinician", "submit_claim",
}
DESTRUCTIVE_TOOLS = {"delete_file", "delete_email", "delete_record"}
EMAIL_TOOLS = {"send_email"}
NETWORK_TOOLS = {"http_post", "http_get", "fetch_url", "browser_open"}
SHELL_TOOLS = {"shell", "bash", "exec", "run_command"}
READ_TOOLS = {"read_file", "list_files", "read_inbox", "search_files", "read_calendar"}

_SAFE_SHELL_COMMANDS = {"ls", "pwd", "date", "wc", "head", "tail", "cat", "grep", "echo"}
_SHELL_METACHARACTERS = re.compile(r"[|;&<>`$()\n]")
_SHELL_NETWORK = re.compile(r"\b(curl|wget|nc|ncat|scp|sftp|ssh|rsync|ftp)\b")
_SHELL_PIPE_TO_INTERPRETER = re.compile(r"\|\s*(sudo\s+)?(sh|bash|zsh|python\d?|perl|ruby)\b")
_PROTECTED_PATH = re.compile(r"(\.ssh|id_rsa|\.aws|\.gnupg|keychain|credentials|\.env\b)", re.I)

MAX_DISPLAY_CHARS = 200


@dataclass
class Verdict:
    decision: str  # "allow" | "ask" | "block"
    title: str = ""
    facts: list[tuple[str, str]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def _luhn_valid(digits: str) -> bool:
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def classify(text: str, canaries: Iterable[str]) -> set[str]:
    """Return the sensitivity labels present in `text`; empty means safe for the cloud."""
    labels = {"canary"} if any(c in text for c in canaries) else set()
    for label, patterns in _PATTERNS.items():
        if any(p.search(text) for p in patterns):
            labels.add(label)
    for match in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            labels.add("financial")
    return labels


def display(value: Any) -> str:
    """Make attacker-controllable text safe to show on an approval card.

    Non-ASCII is escaped so a lookalike domain cannot pass for the real one.
    """
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=True)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text).encode("ascii", "backslashreplace").decode()
    return text if len(text) <= MAX_DISPLAY_CHARS else text[:MAX_DISPLAY_CHARS] + "..."


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _data_flow_warnings(session_labels: set[str]) -> list[str]:
    readable = sorted(session_labels - {"canary", "opaque"})
    if readable:
        return [f"This session has read {' and '.join(readable)} data"]
    if session_labels:
        return ["This session has handled protected data"]
    return []


def _review_email(args: dict, labels: set[str], settings: Settings) -> Verdict:
    recipients = _as_list(args.get("to")) + _as_list(args.get("cc")) + _as_list(args.get("bcc"))
    known = {r.lower() for r in settings.known_recipients}
    unknown = [r for r in recipients if r.lower() not in known]
    if recipients and not unknown:
        return Verdict("allow")
    facts = [
        ("To", display(", ".join(recipients) or "(no recipient)")),
        ("Subject", display(args.get("subject", ""))),
        ("Body", display(args.get("body", ""))),
    ]
    reasons = ["You've never approved this recipient"] + _data_flow_warnings(labels)
    return Verdict("ask", "Agent wants to send an email", facts, reasons)


def _review_network(name: str, args: dict, labels: set[str], settings: Settings) -> Verdict:
    url = str(args.get("url", ""))
    host = (urlsplit(url).hostname or "").lower()
    if host and host in {h.lower() for h in settings.allowed_hosts}:
        return Verdict("allow")
    facts = [("Destination", display(host or url or "(no url)"))]
    if "data" in args or "body" in args:
        facts.append(("Data", display(args.get("data", args.get("body")))))
    reasons = ["This destination is not on your allowed list"] + _data_flow_warnings(labels)
    return Verdict("ask", "Agent wants to contact a website", facts, reasons)


def _review_shell(args: dict, labels: set[str]) -> Verdict:
    command = str(args.get("command", args.get("cmd", "")))
    reasons: list[str] = []
    if _SHELL_NETWORK.search(command):
        reasons.append("This command reaches the network")
    if _SHELL_PIPE_TO_INTERPRETER.search(command):
        reasons.append("This command runs code it pipes in")
    if re.search(r"\brm\b", command):
        reasons.append("This command deletes files")
    if _PROTECTED_PATH.search(command):
        reasons.append("This command touches credentials")
    if not reasons and not _SHELL_METACHARACTERS.search(command):
        try:
            argv = shlex.split(command)
        except ValueError:
            argv = []
        if argv and argv[0] in _SAFE_SHELL_COMMANDS:
            return Verdict("allow")
    reasons = (reasons or ["The firewall can't tell what this command does"])
    reasons += _data_flow_warnings(labels)
    return Verdict("ask", "Agent wants to run a command", [("Command", display(command))], reasons)


def _review_read(name: str, args: dict, labels: set[str]) -> Verdict:
    target = str(args.get("path", args.get("query", "")))
    if not _PROTECTED_PATH.search(target):
        return Verdict("allow")
    return Verdict(
        "ask",
        "Agent wants to read a credentials file",
        [("File", display(target))],
        ["This file can hold passwords or keys"] + _data_flow_warnings(labels),
    )


def _review_sensitive_action(name: str, args: dict, title: str, labels: set[str]) -> Verdict:
    facts = [(key.replace("_", " ").capitalize(), display(value)) for key, value in args.items()]
    return Verdict("ask", title, facts, ["This action always needs you"] + _data_flow_warnings(labels))


def review_tool_call(
    name: str, raw_arguments: str, session_labels: set[str], settings: Settings
) -> Verdict:
    """Decide what happens to one tool call the model asked for."""
    if any(canary in raw_arguments for canary in settings.canaries):
        return Verdict(
            "block",
            "Blocked: agent tried to use a protected secret",
            [("Tool", display(name))],
            ["A planted secret appeared in this action"],
        )
    try:
        args = json.loads(raw_arguments or "{}")
    except (TypeError, ValueError):
        args = None
    if not isinstance(args, dict):
        return Verdict(
            "block",
            "Blocked: unreadable action",
            [("Tool", display(name))],
            ["The firewall could not parse this action"],
        )

    if name in EMAIL_TOOLS:
        return _review_email(args, session_labels, settings)
    if name in NETWORK_TOOLS:
        return _review_network(name, args, session_labels, settings)
    if name in SHELL_TOOLS:
        return _review_shell(args, session_labels)
    if name in READ_TOOLS:
        return _review_read(name, args, session_labels)
    if name in MONEY_TOOLS:
        return _review_sensitive_action(name, args, "Agent wants to move money", session_labels)
    if name in HEALTH_WRITE_TOOLS:
        return _review_sensitive_action(name, args, "Agent wants to change a health record", session_labels)
    if name in DESTRUCTIVE_TOOLS:
        return _review_sensitive_action(name, args, "Agent wants to delete something", session_labels)
    return Verdict(
        "ask",
        "Agent wants to use an unknown tool",
        [("Tool", display(name)), ("Details", display(args))],
        ["The firewall doesn't recognize this tool"] + _data_flow_warnings(session_labels),
    )
