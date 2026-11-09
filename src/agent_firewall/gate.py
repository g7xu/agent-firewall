"""Reviews Claude Code tool requests, reusing the shared tool policy.

A file is scanned before the agent opens it, because once a read happens the
contents are already on their way to the model provider.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from .config import Settings
from .policy import Verdict, _folded, _names_secret, classify, display, review_tool_call

MAX_SCAN_BYTES = 5_000_000
MAX_SCAN_FILES = 500
_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}
# Writes here need a person: `.git/config` alone can make the auto-allowed `git status` run a command.
_EXECUTABLE_CONFIG = re.compile(
    r"(^|/)(\.(claude|codex|muse|git|vscode|idea)(/|$)|\.(envrc|gitattributes|gitmodules)$)"
)

# Metadata-only tools: they reveal no file contents and take no outside action.
_NO_DATA_TOOLS = {
    "Glob", "LS", "TodoWrite", "ToolSearch", "Task", "Agent", "TaskOutput",
    "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "EnterPlanMode", "ExitPlanMode",
    "AskUserQuestion",
}
_READ_ONLY_GIT = {"git status", "git status --short", "git branch", "git log --oneline"}
_FILE_READING_COMMANDS = {"cat", "head", "tail", "grep", "wc"}
_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_LABEL_REASONS = {
    "financial": "Contains financial data",
    "health": "Contains health data",
    "canary": "Contains a planted secret",
    "opaque": "The firewall can't inspect this",
    "credentials": "Contains files that can hold passwords or keys",
}
CLOUD_WARNING = "Allowing sends this to Anthropic's cloud"


@dataclass
class Review:
    verdict: Verdict
    target: str = ""
    labels: set[str] = field(default_factory=set)
    keep_local_path: str | None = None


def _scan_file(path: Path, settings: Settings) -> set[str]:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return {"opaque"}
        raw = path.read_bytes()
    except OSError:
        return {"opaque"}
    if b"\x00" in raw:
        return {"opaque"}
    try:
        return classify(raw.decode("utf-8"), settings.canaries)
    except UnicodeDecodeError:
        return {"opaque"}


def scan_path(path: str, settings: Settings) -> set[str]:
    """Return labels for a file or directory; a directory too big to finish counts as opaque."""
    target = Path(os.path.realpath(path))
    if target.is_file():
        return _scan_file(target, settings)
    labels: set[str] = set()
    scanned = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            scanned += 1
            if scanned > MAX_SCAN_FILES:
                return labels | {"opaque"}
            # Keys and tokens rarely match the data patterns, so the file name has to count.
            labels |= {"credentials"} if _names_secret(name) else _scan_file(Path(root, name), settings)
    return labels


def _resolve(path: str, cwd: str) -> str:
    return os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))


def _project_relative(path: str, cwd: str) -> str:
    """Express a resolved path from the project root; one outside the project stays absolute."""
    real_cwd = os.path.realpath(cwd)
    inside = path == real_cwd or path.startswith(real_cwd + os.sep)
    return os.path.relpath(path, real_cwd) if inside else path


def _shown_path(path: str, cwd: str) -> str:
    return display(_project_relative(path, cwd))


def _named(verdict: Verdict) -> Verdict:
    verdict.title = verdict.title.replace("Agent", "Claude Code", 1)
    return verdict


def _sensitive_read(path: str, cwd: str, found: set[str], prior: list[str]) -> Verdict:
    reasons = [_LABEL_REASONS[label] for label in sorted(found) if label in _LABEL_REASONS]
    return Verdict(
        "ask", "Claude Code wants to read a sensitive file",
        [("File", _shown_path(path, cwd))], reasons + prior + [CLOUD_WARNING],
    )


def _review_read(tool_input: dict, cwd: str, labels: set[str], settings: Settings) -> Review:
    path = _resolve(str(tool_input.get("file_path", "")), cwd)
    args = {"path": _project_relative(path, cwd)}
    base = review_tool_call("read_file", json.dumps(args), labels, settings)
    target = _shown_path(path, cwd)
    if base.decision == "block":
        return Review(base, target)
    found = scan_path(path, settings) if os.path.exists(path) else set()
    if not found:
        return Review(_named(base), target)
    verdict = _sensitive_read(path, cwd, found, base.reasons)
    can_summarize = os.path.isfile(path) and "opaque" not in found
    return Review(verdict, target, found, path if can_summarize else None)


def _review_grep(tool_input: dict, cwd: str, labels: set[str], settings: Settings) -> Review:
    path = _resolve(str(tool_input.get("path") or "."), cwd)
    target = _shown_path(path, cwd)
    args = {"path": _project_relative(path, cwd)}
    # Not search_files, which refuses ".": here the root is known and scan_path bounds the walk.
    base = review_tool_call("read_file", json.dumps(args), labels, settings)
    if base.decision != "allow":
        return Review(_named(base), target)
    found = scan_path(path, settings) if os.path.exists(path) else set()
    if not found:
        return Review(base, target)
    return Review(_sensitive_read(path, cwd, found, []), target, found)


def _review_bash(tool_input: dict, cwd: str, labels: set[str], settings: Settings) -> Review:
    command = tool_input.get("command")
    if command in _READ_ONLY_GIT:
        return Review(Verdict("allow"), display(command))
    shown = display(command)
    base = review_tool_call("shell", json.dumps({"command": command}), labels, settings)
    if base.decision != "allow":
        return Review(_named(base), shown)
    argv = str(command).split()
    if argv and argv[0] in _FILE_READING_COMMANDS:
        found: set[str] = set()
        for arg in argv[1:]:
            path = _resolve(arg, cwd)
            if not arg.startswith("-") and os.path.exists(path):
                found |= scan_path(path, settings)
        if found:
            verdict = _sensitive_read(cwd, cwd, found, [])
            verdict.facts = [("Command", shown)]
            return Review(verdict, shown, found)
    return Review(base, shown)


def _review_write(tool: str, tool_input: dict, cwd: str, settings: Settings) -> Review:
    raw_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    path = _resolve(raw_path, cwd)
    target = _shown_path(path, cwd)
    if any(canary in json.dumps(tool_input) for canary in settings.canaries):
        return Review(
            Verdict("block", "Blocked: Claude Code tried to write a protected secret",
                    [("File", target)], ["A planted secret appeared in this action"]),
            target,
        )
    # Folded because default macOS volumes treat .GIT and .git as the same directory.
    if _EXECUTABLE_CONFIG.search(_folded(path)):
        return Review(
            Verdict("ask", "Claude Code wants to change settings that can run code", [("File", target)],
                    ["These settings can run commands or turn off this firewall"]),
            target,
        )
    if not path.startswith(os.path.realpath(cwd) + os.sep):
        return Review(
            Verdict("ask", "Claude Code wants to change a file outside this project",
                    [("File", target)], ["This file is outside the current project"]),
            target,
        )
    return Review(Verdict("allow"), target)


def review_claude_code(payload: dict, session_labels: set[str], settings: Settings) -> Review:
    """Decide one PreToolUse event. Tools not handled here fall through to the shared policy."""
    tool = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    cwd = str(payload.get("cwd") or os.getcwd())
    settings = replace(settings, agent_workdir=os.path.realpath(cwd))

    if tool in _NO_DATA_TOOLS:
        return Review(Verdict("allow"), "")
    if tool == "Read":
        return _review_read(tool_input, cwd, session_labels, settings)
    if tool == "Grep":
        return _review_grep(tool_input, cwd, session_labels, settings)
    if tool == "Bash":
        return _review_bash(tool_input, cwd, session_labels, settings)
    if tool in _WRITE_TOOLS:
        return _review_write(tool, tool_input, cwd, settings)
    if tool == "WebFetch":
        url = {"url": tool_input.get("url")}
        return Review(_named(review_tool_call("fetch_url", json.dumps(url), session_labels, settings)),
                      display(url["url"]))
    if tool == "WebSearch":
        query = display(tool_input.get("query", ""))
        if not session_labels:
            return Review(Verdict("allow"), query)
        return Review(
            Verdict("ask", "Claude Code wants to search the web", [("Search", query)],
                    ["This session has read protected data"]),
            query,
        )
    return Review(_named(review_tool_call(tool, json.dumps(tool_input), session_labels, settings)),
                  display(tool))
