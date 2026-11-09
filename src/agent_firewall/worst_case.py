"""Plain-language worst case for an approval card.

The fixed sentence is always shown. A small local model may add a more specific one beside it,
labeled as AI-written, because no filter can prove a generated sentence doesn't understate the
risk. The model receives only facts the rules extracted, never file contents or message bodies,
since that text can carry an instruction to play the risk down.
"""

from __future__ import annotations

import asyncio
import re

import httpx

from .config import Settings
from .policy import Verdict, display

MODEL_DEADLINE_SECONDS = 3.0
_MAX_TOKENS = 60
_MIN_CHARS = 20
_MAX_CHARS = 180

_GENERIC = "The firewall can't predict this, so it could do something you never intended."
_FIXED = {
    "read a sensitive file": "This data leaves your Mac and can't be taken back.",
    "run a command that reads sensitive files": "This data leaves your Mac and can't be taken back.",
    "run a command that may read sensitive files": "Private data in this folder could leave your Mac and can't be taken back.",
    "search a folder with sensitive files": "Private data in these files leaves your Mac and can't be taken back.",
    "read a credentials file": "Anyone who gets this file could sign in as you.",
    "move money": "The money is gone and may not be recoverable.",
    "send an email": "Private information reaches a stranger.",
    "contact a website": "Your data reaches a site you don't control.",
    "change a health record": "A medical record is changed or shared in a way you can't undo.",
    "delete something": "It may be gone for good.",
    "change settings that can run code": "A planted command runs as you, and this firewall can be turned off.",
    "change a file outside this project": "A file you rely on changes without you noticing.",
    "search the web": "Private details from this session end up with a search engine.",
}
# First matching reason wins, so the order runs from most to least severe.
_COMMAND_RISKS = (
    ("runs code it pipes in", "That code runs as you and can reach all your files."),
    ("touches credentials", "Anyone who gets these could sign in as you."),
    ("deletes files", "These files may be gone for good."),
    ("reaches the network", "Your files could be sent to someone else."),
)
_COMMAND_DEFAULT = "This command could do anything you can do on this Mac."

# Only these fields reach the model, and only when they look like plain identifiers. Each is
# phrased as a sentence because small models reverse direction when given bare key=value pairs.
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}")
_HOST = re.compile(r"[A-Za-z0-9.-]{1,190}")
_ACCOUNT = re.compile(r"[A-Za-z0-9-]{1,34}")
_MONEY = re.compile(r"\d{1,12}(?:\.\d{1,2})?")
_MODEL_FACTS = {
    "To": ("It goes to {}.", _EMAIL),
    "Destination": ("The data goes to {}.", _HOST),
    "To account": ("The money goes to account {}.", _ACCOUNT),
    "Recipient": ("It is shared with {}.", _EMAIL),
    "Account": ("The account involved is {}.", _ACCOUNT),
    "Amount": ("The amount is {}.", _MONEY),
    "Amount usd": ("The amount is ${}.", _MONEY),
}
_DATA_REASON = re.compile(r"^(Contains |This session has read )")

_REASSURING_OR_ADVICE = re.compile(
    r"\b(safe|safely|harmless|nothing|unlikely|fine|okay|ok|secure|ignore|approve|allow|click"
    r"|should|recommend\w*|no (risk|problem|harm)|not a problem|don'?t worry)\b",
    re.I,
)
_OVERSTATED_OR_REVERSED = re.compile(
    r"\b(death|die|fatal|forever|catastroph\w*|all data|entire (?:system|device|computer|amount)"
    r"|operating system|from (?:your )?account)\b",
    re.I,
)
_SPELLED_AMOUNT = re.compile(r"\b(hundred|thousand|million|billion|dozen)s?\b", re.I)
_NUMBER = re.compile(r"\d[\d,.]*")
_ADDRESS = re.compile(r"[\w.-]+@[\w.-]+|\b[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b", re.I)
_INSTRUCTIONS = (
    "You write one short warning for a person deciding whether to let an AI agent act. "
    "Using only the facts given, rewrite the warning so it is specific. State the worst realistic "
    "outcome of this one action, in proportion, addressing the reader as you. Do not reassure. "
    "Do not invent numbers, names or places. Output one sentence under 25 words and nothing else."
)


def _action(verdict: Verdict) -> str:
    return verdict.title.split(" wants to ", 1)[-1]


def fixed_worst_case(verdict: Verdict) -> str:
    action = _action(verdict)
    if action == "run a command":
        reasons = " ".join(verdict.reasons)
        return next((text for marker, text in _COMMAND_RISKS if marker in reasons), _COMMAND_DEFAULT)
    return _FIXED.get(action, _GENERIC)


def _usable_facts(verdict: Verdict) -> dict[str, str]:
    """Keep each allowed field once, and only when its value has exactly the expected shape."""
    usable: dict[str, str] = {}
    for label, value in verdict.facts:
        if label in usable:
            continue
        if label in _MODEL_FACTS and _MODEL_FACTS[label][1].fullmatch(value):
            usable[label] = value
    return usable


def _model_input(verdict: Verdict, fixed: str, facts: dict[str, str]) -> str:
    lines = [f"An AI agent wants to {_action(verdict)}."]
    lines += [f"{reason}." for reason in verdict.reasons if _DATA_REASON.match(reason)]
    lines += [_MODEL_FACTS[label][0].format(value) for label, value in facts.items()]
    return f"Warning: {fixed}\nFacts: " + " ".join(lines)


def _digits(text: str) -> str:
    return text.replace(",", "").rstrip(".")


def _acceptable(text: str, facts: dict[str, str]) -> bool:
    """Reject wording that plays down the risk, or that states anything the facts don't.

    Numbers and addresses must equal a whole fact value: "98" is not in "9800".
    """
    if not _MIN_CHARS <= len(text) <= _MAX_CHARS or "\n" in text:
        return False
    if (
        _REASSURING_OR_ADVICE.search(text)
        or _OVERSTATED_OR_REVERSED.search(text)
        or _SPELLED_AMOUNT.search(text)
    ):
        return False
    known_numbers = {_digits(n) for value in facts.values() for n in _NUMBER.findall(value)}
    known_addresses = {a.lower() for value in facts.values() for a in _ADDRESS.findall(value)}
    return all(_digits(n) in known_numbers for n in _NUMBER.findall(text)) and all(
        a.lower() in known_addresses for a in _ADDRESS.findall(text)
    )


async def _ask_model(prompt: str, settings: Settings, client: httpx.AsyncClient) -> str:
    prefix = "/no_think\n" if settings.worst_case_model.startswith("qwen3") else ""
    response = await client.post(
        f"{settings.local_base_url}/chat/completions",
        json={
            "model": settings.worst_case_model, "stream": False, "temperature": 0.2,
            "max_tokens": _MAX_TOKENS,
            "messages": [
                {"role": "system", "content": _INSTRUCTIONS},
                {"role": "user", "content": prefix + prompt},
            ],
        },
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"] or ""


async def ai_worst_case(verdict: Verdict, settings: Settings, client: httpx.AsyncClient) -> str:
    """Return the model's specific sentence, or "" if it didn't qualify in time."""
    if not settings.worst_case_model:
        return ""
    fixed = fixed_worst_case(verdict)
    facts = _usable_facts(verdict)
    prompt = _model_input(verdict, fixed, facts)
    try:
        raw = await asyncio.wait_for(_ask_model(prompt, settings, client), MODEL_DEADLINE_SECONDS)
    except (TimeoutError, httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
        return ""
    text = re.sub(r"^\s*warning:\s*", "", raw.strip(), flags=re.I).strip()
    return display(text) if _acceptable(text, facts) else ""


async def warm_up(settings: Settings, client: httpx.AsyncClient) -> None:
    """Load the model at startup so the first popup doesn't miss the deadline."""
    if not settings.worst_case_model:
        return
    try:
        await _ask_model("Warning: test\nFacts: action=test", settings, client)
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
        pass
