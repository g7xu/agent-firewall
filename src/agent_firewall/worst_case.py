"""Plain-language worst case for an approval card.

The fixed sentences are the guarantee. A small local model may make one more specific, but it
receives only facts the rules extracted, never file contents or message bodies, because that
text can carry an instruction to play the risk down. Its output is thrown away unless it
passes every check in `_acceptable`.
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
_MODEL_FACTS = {
    "To": "It goes to {}.",
    "Destination": "The data goes to {}.",
    "To account": "The money goes to account {}.",
    "Recipient": "It is shared with {}.",
    "Account": "The account involved is {}.",
    "Amount": "The amount is {}.",
    "Amount usd": "The amount is ${}.",
}
_PLAIN_FACT = re.compile(r"[A-Za-z0-9@._:/$, -]{1,80}")
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


def _model_input(verdict: Verdict, fixed: str) -> str:
    facts = [f"An AI agent wants to {_action(verdict)}."]
    facts += [f"{reason}." for reason in verdict.reasons if _DATA_REASON.match(reason)]
    facts += [
        _MODEL_FACTS[label].format(value)
        for label, value in verdict.facts
        if label in _MODEL_FACTS and _PLAIN_FACT.fullmatch(value)
    ]
    return f"Warning: {fixed}\nFacts: " + " ".join(facts)


def _digits(text: str) -> str:
    return text.replace(",", "").rstrip(".")


def _acceptable(text: str, source: str) -> bool:
    """Reject wording that plays down the risk, or that states anything the facts don't."""
    if not _MIN_CHARS <= len(text) <= _MAX_CHARS or "\n" in text:
        return False
    if _REASSURING_OR_ADVICE.search(text) or _OVERSTATED_OR_REVERSED.search(text):
        return False
    known_digits = _digits(source)
    if any(_digits(number) not in known_digits for number in _NUMBER.findall(text)):
        return False
    return all(address.lower() in source.lower() for address in _ADDRESS.findall(text))


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


async def describe_worst_case(verdict: Verdict, settings: Settings, client: httpx.AsyncClient) -> str:
    """Return the sentence for the card: the model's if it qualifies in time, otherwise the fixed one."""
    fixed = fixed_worst_case(verdict)
    if not settings.worst_case_model:
        return fixed
    prompt = _model_input(verdict, fixed)
    try:
        raw = await asyncio.wait_for(_ask_model(prompt, settings, client), MODEL_DEADLINE_SECONDS)
    except (TimeoutError, httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
        return fixed
    text = re.sub(r"^\s*warning:\s*", "", raw.strip(), flags=re.I).strip()
    return display(text) if _acceptable(text, prompt) else fixed


async def warm_up(settings: Settings, client: httpx.AsyncClient) -> None:
    """Load the model at startup so the first popup doesn't miss the deadline."""
    if not settings.worst_case_model:
        return
    try:
        await _ask_model("Warning: test\nFacts: action=test", settings, client)
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
        pass
