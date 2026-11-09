"""Native macOS confirmation dialog."""

from __future__ import annotations

import asyncio

# Card text arrives through argv: a file name can never become AppleScript source.
_SCRIPT = """on run argv
  set theButtons to {"Deny", "Allow"}
  if item 3 of argv is "keep" then set theButtons to {"Deny", "Keep on my Mac", "Allow"}
  set answer to display dialog (item 1 of argv) with title "Agent Firewall" buttons theButtons default button "Deny" with icon caution giving up after (item 2 of argv as integer)
  if gave up of answer then return "Deny"
  return button returned of answer
end run"""
_DECISIONS = {"Allow": "approve", "Deny": "deny", "Keep on my Mac": "keep_local"}


def card_text(title: str, facts: list[tuple[str, str]], reasons: list[str]) -> str:
    lines = [title, ""] + [f"{label}: {value}" for label, value in facts]
    return "\n".join(lines + [""] + [f"⚠ {reason}" for reason in reasons])


async def ask_on_mac(text: str, timeout_seconds: int, can_keep_local: bool) -> str | None:
    """Show the dialog and return a decision, or None if no dialog could be shown."""
    try:
        process = await asyncio.create_subprocess_exec(
            "osascript", "-e", _SCRIPT, text, str(timeout_seconds), "keep" if can_keep_local else "plain",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return None
    try:
        stdout, _ = await process.communicate()
    except asyncio.CancelledError:
        process.kill()
        raise
    return _DECISIONS.get(stdout.decode().strip())
