"""Deterministic data labeling and tool-call review.

Everything here is plain code on purpose: model output and tool results are
attacker-influenced, so no decision in this module may depend on a model.
Tools the policy has never heard of are held for a human, never allowed.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

from .config import Settings

_EXACT_FORMATS = {
    "financial": [
        re.compile(p, re.I) for p in (r"\bACCT-\d{6,}\b", r"\b\d{3}-\d{2}-\d{4}\b")
    ],
    "health": [re.compile(r"\bMRN-?\d{5,}\b", re.I)],
}
_TOPIC_WORDS = {
    "financial": [
        re.compile(p, re.I)
        for p in (
            r"\baccount (?:number|no\.?)\b",
            r"\brouting (?:number|no\.?)\b",
            r"\bstatement balance\b",
            r"\bIBAN\b",
        )
    ],
    "health": [
        re.compile(p, re.I)
        for p in (
            r"\bdiagnos(?:is|ed)\b",
            r"\bprescri(?:ption|bed)\b",
            r"\blab results?\b",
            r"\bpatient note\b",
            r"\bA1C\b",
        )
    ],
}
_DIGIT_RUN = re.compile(r"\b\d+(?:[ -]\d+)*\b")

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
_PATH_REQUIRED_TOOLS = {"read_file", "search_files"}
_RECURSIVE_READ_TOOLS = {"search_files"}

_EMAIL_FIELDS = {"to", "cc", "bcc", "subject", "body"}
_NETWORK_FIELDS = {"url", "data", "body"}
_READ_FIELDS = {"path", "query"}
_UNKNOWN_FIELDS_REASON = "This action has fields the firewall doesn't recognize"

_DIGITS = "0123456789"
# Short-flag letters each auto-allowed command may carry. Deliberately absent: grep -r/-R/-d/-D/-f,
# ls -R and date -s/-f/-r, which reach files no argument names or change system state. Long options
# never qualify: they can be abbreviated and can carry a path after "=".
_SAFE_SHELL_COMMANDS = {
    "ls": "1AFSadhilprt",
    "pwd": "LP",
    "date": "IRu",
    "wc": "Lclmw",
    "head": "cn" + _DIGITS,
    "tail": "cn" + _DIGITS,
    "cat": "AETbenstuv",
    "grep": "ABCEFGHILacehilnoqsvwx" + _DIGITS,
    "echo": "Een",
}
# Characters every shell passes through literally, so splitting on spaces yields the real argv.
# Quotes, backslashes, globs, braces, tilde and operators all fall outside this set.
_SHELL_LITERAL = re.compile(r"[A-Za-z0-9_./:,@%+ -]+")
_SHELL_NETWORK = re.compile(r"\b(curl|wget|nc|ncat|scp|sftp|ssh|rsync|ftp)\b")
_SHELL_PIPE_TO_INTERPRETER = re.compile(r"\|\s*(sudo\s+)?(sh|bash|zsh|python\d?|perl|ruby)\b")
# Matched against _folded text only. A name list can never be complete, so _has_hidden_part holds
# every other dotfile; this list names the secrets that need no leading dot, and titles the card.
_PROTECTED_PATH = re.compile(
    r"\.ssh|\.aws|\.gnupg|\.azure|\.kube|kubeconfig|\.docker|\.config/(?:gh|gcloud)|\.git/config"
    r"|\.env|\.netrc|_netrc|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)|\.(?:pem|key|p12|pfx|jks|keystore|tfstate|tfvars)\b"
    r"|keychain|credentials|secret|passw(?:or)?d|private.?key|api.?key|access.?token"
    r"|shadow|sudoers|cookies|login.?data"
)
# No tilde, glob, brace, backslash, percent, colon or non-ASCII: any of those can mean a different
# file to a tool that expands, decodes or normalizes its path before opening it.
_PLAIN_PATH = re.compile(r"[A-Za-z0-9_./-]+")
_URL_AMBIGUOUS = re.compile(r"[\\\s\x00-\x1f\x7f-\x9f]")
# A raw line break in a subject starts a new header; a lone "." line ends an SMTP message.
_UNSAFE_SUBJECT = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_UNSAFE_BODY = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]|^\.$", re.M)

MAX_PREVIEW_CHARS = 200
# An approval covers the whole call, so nothing on a card may be cut. An action too long to read
# in full on a phone is blocked instead of being shown in part.
MAX_REVIEWABLE_CHARS = 4000
_MAX_JSON_DECODES = 3
_MAX_EXPANDED_EXPONENT = 64


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


def _contains_card(text: str) -> bool:
    """Try every contiguous span of digit groups, since an expiry or CVV can sit beside the number."""
    for run in _DIGIT_RUN.finditer(text):
        groups = re.split(r"[ -]", run.group())
        for start in range(len(groups)):
            digits = ""
            for group in groups[start:]:
                digits += group
                if len(digits) > 19:
                    break
                if len(digits) >= 13 and _luhn_valid(digits):
                    return True
    return False


def classify(text: str, canaries: Iterable[str], *, exact_only: bool = False) -> set[str]:
    """Return the sensitivity labels present in `text`; empty means safe for the cloud.

    `exact_only` skips topic words, for text such as a tool schema that can name a subject without
    holding any data about it.
    """
    labels = {"canary"} if any(c in text for c in canaries) else set()
    for group in (_EXACT_FORMATS,) if exact_only else (_EXACT_FORMATS, _TOPIC_WORDS):
        for label, patterns in group.items():
            if any(p.search(text) for p in patterns):
                labels.add(label)
    if _contains_card(text):
        labels.add("financial")
    return labels


def display(value: Any) -> str:
    """Make attacker-controllable text safe to show on an approval card, keeping all of it.

    Non-ASCII is escaped so a lookalike domain cannot pass for the real one.
    """
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=True)
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text).encode("ascii", "backslashreplace").decode()


def preview(value: Any) -> str:
    """Shorten commentary that sits beside an action; never use this for the action itself."""
    text = display(value)
    return text if len(text) <= MAX_PREVIEW_CHARS else text[:MAX_PREVIEW_CHARS] + "..."


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


def _extra_field_facts(args: dict, known: set[str]) -> list[tuple[str, str]]:
    """Approval-card rows for arguments the policy cannot account for; empty means none."""
    return [
        (f"Extra field: {display(key)}", display(value))
        for key, value in args.items()
        if key not in known
    ]


def _email_text_is_plain(args: dict) -> bool:
    """False when a subject or body could carry a recipient the human never approved."""
    return all(
        key not in args or (isinstance(args[key], str) and not unsafe.search(args[key]))
        for key, unsafe in (("subject", _UNSAFE_SUBJECT), ("body", _UNSAFE_BODY))
    )


def _review_email(args: dict, labels: set[str], settings: Settings) -> Verdict:
    recipients = _as_list(args.get("to")) + _as_list(args.get("cc")) + _as_list(args.get("bcc"))
    known = {r.lower() for r in settings.known_recipients}
    unknown = [r for r in recipients if r.lower() not in known]
    extras = _extra_field_facts(args, _EMAIL_FIELDS)
    unapproved = unknown or not recipients
    plain_text = _email_text_is_plain(args)
    if not unapproved and not extras and plain_text:
        return Verdict("allow")
    facts = [
        ("To", display(", ".join(recipients) or "(no recipient)")),
        ("Subject", display(args.get("subject", ""))),
        ("Body", display(args.get("body", ""))),
        *extras,
    ]
    reasons = ["You've never approved this recipient"] if unapproved else []
    reasons += ["The subject or body has structure that could add hidden recipients"] if not plain_text else []
    reasons += ([_UNKNOWN_FIELDS_REASON] if extras else []) + _data_flow_warnings(labels)
    return Verdict("ask", "Agent wants to send an email", facts, reasons)


def _unambiguous_host(url: Any) -> str | None:
    """Return the lowercase hostname of an http(s) URL every client would read the same way.

    None covers everything else, including backslashes, userinfo and whitespace, where parsers
    disagree and the host seen here may not be the host a client connects to.
    """
    if not isinstance(url, str) or _URL_AMBIGUOUS.search(url):
        return None
    try:
        parts = urlsplit(url)
        parts.port  # raises on a malformed port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or "@" in parts.netloc or not parts.hostname:
        return None
    return parts.hostname.lower()


def _review_network(name: str, args: dict, labels: set[str], settings: Settings) -> Verdict:
    url = args.get("url")
    host = _unambiguous_host(url)
    extras = _extra_field_facts(args, _NETWORK_FIELDS)
    host_allowed = host in {h.lower() for h in settings.allowed_hosts}
    plain_payload = all(isinstance(args[key], str) for key in ("data", "body") if key in args)
    if host_allowed and not extras and plain_payload:
        return Verdict("allow")
    # An ambiguous URL is shown whole: its parsed host is exactly what cannot be trusted.
    facts = [("Destination", display(host or url or "(no url)"))]
    if host and url != host:
        facts.append(("Full address", display(url)))
    facts += [(key.capitalize(), display(args[key])) for key in ("data", "body") if key in args]
    facts += extras
    reasons = [] if host_allowed else ["This destination is not on your allowed list"]
    reasons += ["The payload has structure the firewall can't interpret"] if not plain_payload else []
    reasons += ([_UNKNOWN_FIELDS_REASON] if extras else []) + _data_flow_warnings(labels)
    return Verdict("ask", "Agent wants to contact a website", facts, reasons)


def _folded(text: str) -> str:
    """Spell `text` the way a case-insensitive filesystem would compare it, so `.ßh` reads `.ssh`."""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return "".join(char for char in normalized if unicodedata.category(char) not in ("Cc", "Cf"))


def _names_secret(text: str) -> bool:
    return bool(_PROTECTED_PATH.search(_folded(text)))


def _has_hidden_part(path: str) -> bool:
    """True for a dotfile, a dot-directory or a parent reference anywhere in `path`."""
    return any(part.startswith(".") and part != "." for part in path.split("/"))


def _follows_link_out(path: str, workdir: str) -> bool:
    """True when symlinks carry relative `path` out of `workdir` or onto a secret inside it.

    Only literal text can be judged without `workdir`, so an empty one always answers False.
    """
    if not workdir:
        return False
    root = os.path.realpath(workdir)
    relative = os.path.relpath(os.path.realpath(os.path.join(root, path)), root)
    return _has_hidden_part(relative) or _names_secret(relative)


def _shell_is_plainly_safe(command: str, workdir: str) -> bool:
    """True only when every token is literally understood and names nothing out of bounds.

    A symlinked operand is invisible in the text, so catching one needs `workdir`.
    """
    if not _SHELL_LITERAL.fullmatch(command):
        return False
    argv = command.split()
    if not argv or argv[0] not in _SAFE_SHELL_COMMANDS:
        return False
    allowed_flags = set(_SAFE_SHELL_COMMANDS[argv[0]])
    for arg in argv[1:]:
        if arg.startswith("-"):
            if len(arg) < 2 or not set(arg[1:]) <= allowed_flags:
                return False
        elif argv[0] == "date":
            # Any operand other than +FORMAT is a new time for the system clock.
            if not arg.startswith("+"):
                return False
        elif arg.startswith("/") or _has_hidden_part(arg) or _follows_link_out(arg, workdir):
            return False
    return True


def _review_shell(args: dict, labels: set[str], settings: Settings) -> Verdict:
    command = next(iter(args.values())) if set(args) in ({"command"}, {"cmd"}) else None
    shown = command if isinstance(command, str) else json.dumps(args)
    reasons: list[str] = []
    if _SHELL_NETWORK.search(shown):
        reasons.append("This command reaches the network")
    if _SHELL_PIPE_TO_INTERPRETER.search(shown):
        reasons.append("This command runs code it pipes in")
    if re.search(r"\brm\b", shown):
        reasons.append("This command deletes files")
    if _names_secret(shown):
        reasons.append("This command touches credentials")
    if not reasons and isinstance(command, str) and _shell_is_plainly_safe(command, settings.agent_workdir):
        return Verdict("allow")
    reasons = (reasons or ["The firewall can't tell what this command does"])
    reasons += _data_flow_warnings(labels)
    return Verdict("ask", "Agent wants to run a command", [("Command", display(shown))], reasons)


def _is_confined_path(path: Any) -> bool:
    """True for a relative path whose every character means the same thing to any tool."""
    return (
        isinstance(path, str)
        and _PLAIN_PATH.fullmatch(path) is not None
        and not path.startswith(("/", "-"))
        and not _has_hidden_part(path)
    )


def _read_scope_is_clear(name: str, args: dict, workdir: str) -> bool:
    """True when the arguments alone bound what this read can reach."""
    if "path" not in args:
        return name not in _PATH_REQUIRED_TOOLS
    path = args["path"]
    if not _is_confined_path(path) or _follows_link_out(path, workdir):
        return False
    # "." is the agent's whole working directory, which could be as broad as "~".
    return name not in _RECURSIVE_READ_TOOLS or bool(path.strip("./"))


def _review_read(name: str, args: dict, labels: set[str], settings: Settings) -> Verdict:
    values = [args[key] for key in ("path", "query") if key in args]
    target = " ".join(value if isinstance(value, str) else json.dumps(value) for value in values)
    extras = _extra_field_facts(args, _READ_FIELDS)
    protected = _names_secret(target)
    if (
        not protected
        and not extras
        and all(isinstance(value, str) for value in values)
        and _read_scope_is_clear(name, args, settings.agent_workdir)
    ):
        return Verdict("allow")
    title, reason = (
        ("Agent wants to read a credentials file", "This file can hold passwords or keys")
        if protected
        else ("Agent wants to read something unclear", "The firewall can't tell what this reads")
    )
    facts = [("File", display(target)), *extras]
    return Verdict("ask", title, facts, [reason] + _data_flow_warnings(labels))


def _review_sensitive_action(name: str, args: dict, title: str, labels: set[str]) -> Verdict:
    facts = [(key.replace("_", " ").capitalize(), display(value)) for key, value in args.items()]
    return Verdict("ask", title, facts, ["This action always needs you"] + _data_flow_warnings(labels))


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """Refuse repeated keys: the policy and the tool could each honor a different copy."""
    result = dict(pairs)
    if len(result) != len(pairs):
        raise _DuplicateKey
    return result


def _plain_number(number: int | float | Decimal) -> str:
    """Spell a number positionally, so exponent notation cannot disguise its digits."""
    exact = Decimal(repr(number)) if isinstance(number, float) else Decimal(number)
    return format(exact, "f") if abs(exact.adjusted()) <= _MAX_EXPANDED_EXPONENT else str(number)


def inspectable_text(value: Any) -> Iterator[str]:
    """Yield every string and number in `value`, keys included, and inside strings holding JSON.

    Iterative, so nesting depth cannot exhaust the stack. A string is yielded before it is decoded:
    an escape only hides text from a scan of the encoded form.
    """
    stack = [(value, 0)]
    while stack:
        item, decodes = stack.pop()
        if isinstance(item, str):
            yield item
            if decodes < _MAX_JSON_DECODES and item.lstrip()[:1] in ("{", "["):
                try:
                    stack.append((json.loads(item, parse_float=Decimal), decodes + 1))
                except (ValueError, ArithmeticError, RecursionError):
                    pass
        elif isinstance(item, dict):
            stack.extend((part, decodes) for pair in item.items() for part in pair)
        elif isinstance(item, list):
            stack.extend((part, decodes) for part in item)
        elif isinstance(item, (int, float, Decimal)) and not isinstance(item, bool):
            yield _plain_number(item)


def _canary_verdict(name: str) -> Verdict:
    return Verdict(
        "block",
        "Blocked: agent tried to use a protected secret",
        [("Tool", display(name))],
        ["A planted secret appeared in this action"],
    )


def review_tool_call(
    name: str, raw_arguments: str, session_labels: set[str], settings: Settings
) -> Verdict:
    """Decide what happens to one tool call the model asked for."""
    if any(canary in text for text in inspectable_text(raw_arguments) for canary in settings.canaries):
        return _canary_verdict(name)
    try:
        args = json.loads(raw_arguments or "{}", object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        return Verdict(
            "block",
            "Blocked: ambiguous action",
            [("Tool", display(name))],
            ["This action repeats a field, so the firewall can't tell which value a tool would use"],
        )
    except (TypeError, ValueError, RecursionError):
        args = None
    if not isinstance(args, dict):
        return Verdict(
            "block",
            "Blocked: unreadable action",
            [("Tool", display(name))],
            ["The firewall could not parse this action"],
        )

    verdict = _review_by_kind(name, args, session_labels, settings)
    if verdict.decision == "ask" and any(
        len(label) + len(value) > MAX_REVIEWABLE_CHARS for label, value in verdict.facts
    ):
        return Verdict(
            "block",
            "Blocked: action too long to review",
            [("Tool", preview(name))],
            ["This action is too long to show in full on an approval card"],
        )
    return verdict


def _review_by_kind(name: str, args: dict, session_labels: set[str], settings: Settings) -> Verdict:
    if name in EMAIL_TOOLS:
        return _review_email(args, session_labels, settings)
    if name in NETWORK_TOOLS:
        return _review_network(name, args, session_labels, settings)
    if name in SHELL_TOOLS:
        return _review_shell(args, session_labels, settings)
    if name in READ_TOOLS:
        return _review_read(name, args, session_labels, settings)
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
