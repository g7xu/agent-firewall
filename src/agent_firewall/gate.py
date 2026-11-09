"""Reviews Claude Code tool requests, reusing the shared tool policy.

A file is scanned before the agent opens it, because once a read happens the
contents are already on their way to the model provider.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shlex
from dataclasses import dataclass, field, replace
from pathlib import Path

from .clean_search import CleanSearch
from .config import Settings
from .inspector import inspect_file
from .policy import Verdict, _folded, _names_secret, display, inspectable_text, review_tool_call
from .scan_index import ScanIndex

MAX_SCAN_FILES = 500
MAX_WALK_FILES = 200_000
_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}
# Writes here need a person: `.git/config` alone can make the auto-allowed `git status` run a command.
_EXECUTABLE_CONFIG = re.compile(
    r"(^|/)(\.(claude|codex|muse|git|vscode|idea|agent-firewall)(/|$)|\.(envrc|gitattributes|gitmodules)$)"
)

# Metadata-only tools: they reveal no file contents and take no outside action.
_NO_DATA_TOOLS = {
    "Glob", "LS", "TodoWrite", "ToolSearch", "Task", "Agent", "TaskOutput",
    "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "EnterPlanMode", "ExitPlanMode",
    "AskUserQuestion", "Skill",
    # The Claude desktop app's own interface tools: task list, recap, panes and chapter markers.
    "mcp__ccd_turn__update_plan", "mcp__ccd_turn__wrap_up", "mcp__ccd_view__show_pane",
    "mcp__ccd_view__close_pane", "mcp__ccd_view__get_layout", "mcp__ccd_view__set_transcript_view",
    "mcp__ccd_session__mark_chapter",
}
_SHELL_EXPANSION = re.compile(r"[*?\[\]{}~]")
_SEARCH_FLAGS = {"grep": set("rnilHEIcw"), "rg": set("nilHcw")}
MAX_COMMAND_PATHS = 200
MAX_GLOB_MATCHES = 200
MAX_LISTED_FILES = 8
_PATH_LIKE = re.compile(r"[\w.~/*?\[\]-]*[\w*?\]][\w.~/*?\[\]-]*")
_GLOB_CHARS = re.compile(r"[*?\[]")
_COMMAND_SEPARATORS = re.compile(r";|&&|\|\||\||\n")
_COMMAND_SUBSTITUTION = re.compile(r"\$\(|`|<\(|>\(")
_AMBIGUOUS_SHELL = re.compile(r"(?<!&)&(?!&)|[<>]")
# Deliberately absent: date, du and file, whose options can read a list from a file.
_NAME_ONLY_COMMANDS = {"ls", "pwd", "cd", "echo", "which", "mkdir", "stat", "basename", "dirname"}
_FOLDER_READING_COMMANDS = re.compile(r"\b(grep|egrep|fgrep|rg|ag|ack|tar|zip|cp|rsync|scp)\b")
_READ_ONLY_GIT = {"git status", "git status --short", "git branch", "git log --oneline"}
_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_LABEL_REASONS = {
    "financial": "Contains financial data",
    "health": "Contains health data",
    "canary": "Contains a planted secret",
    "opaque": "The firewall can't inspect this",
    "credentials": "Contains files that can hold passwords or keys",
    "identity": "Looks like an identity document",
    "inferred": "Sits in a folder of sensitive files",
}
CLOUD_WARNING = "Allowing sends this to Anthropic's cloud"


@dataclass
class Review:
    verdict: Verdict
    target: str = ""
    labels: set[str] = field(default_factory=set)
    keep_local_path: str | None = None
    clean_search: CleanSearch | None = None


@dataclass
class FolderScan:
    labels: set[str] = field(default_factory=set)
    total: int = 0
    sensitive: int = 0
    unreadable: int = 0
    clean: list[str] = field(default_factory=list)


def scan_folder(path: str, settings: Settings, index: ScanIndex | None = None) -> FolderScan:
    """Check a file or directory, reading at most MAX_SCAN_FILES files that have no saved result."""
    target = Path(os.path.realpath(path))
    scan = FolderScan()

    def record(file: Path, labels: set[str]) -> None:
        scan.total += 1
        scan.labels |= labels
        if labels - {"opaque"}:
            scan.sensitive += 1
        elif labels:
            scan.unreadable += 1
        else:
            scan.clean.append(str(file))

    if target.is_file():
        record(target, inspect_file(target, settings, index).labels)
        return scan
    read_now = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if scan.total >= MAX_WALK_FILES:
                scan.labels.add("opaque")
                return scan
            file = Path(root, name)
            if file.is_symlink():
                # A link can point anywhere, so it never counts as clean.
                record(file, {"opaque"})
                continue
            if _names_secret(name):
                # Keys and tokens rarely match the data patterns, so the file name has to count.
                record(file, {"credentials"})
                continue
            found = inspect_file(file, settings, index, allow_live=read_now < MAX_SCAN_FILES)
            read_now += 1 if found is not None and found.was_live else 0
            record(file, found.labels if found is not None else {"opaque"})
    return scan


def scan_path(path: str, settings: Settings, index: ScanIndex | None = None) -> set[str]:
    """Return labels for a file or directory; a directory too big to finish counts as opaque."""
    return scan_folder(path, settings, index).labels


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


def _review_read(
    tool_input: dict, cwd: str, labels: set[str], settings: Settings, index: ScanIndex | None
) -> Review:
    path = _resolve(str(tool_input.get("file_path", "")), cwd)
    args = {"path": _project_relative(path, cwd)}
    base = review_tool_call("read_file", json.dumps(args), labels, settings)
    target = _shown_path(path, cwd)
    if base.decision == "block":
        return Review(base, target)
    found = scan_path(path, settings, index) if os.path.exists(path) else set()
    if not found:
        return Review(_named(base), target)
    verdict = _sensitive_read(path, cwd, found, base.reasons)
    can_summarize = os.path.isfile(path) and "opaque" not in found
    return Review(verdict, target, found, path if can_summarize else None)


def _review_grep(
    tool_input: dict, cwd: str, labels: set[str], settings: Settings, index: ScanIndex | None
) -> Review:
    path = _resolve(str(tool_input.get("path") or "."), cwd)
    target = _shown_path(path, cwd)
    args = {"path": _project_relative(path, cwd)}
    # Not search_files, which refuses ".": here the root is known and scan_folder bounds the walk.
    base = review_tool_call("read_file", json.dumps(args), labels, settings)
    if base.decision != "allow":
        return Review(_named(base), target)
    scan = scan_folder(path, settings, index) if os.path.exists(path) else FolderScan()
    if not scan.labels:
        return Review(base, target)
    verdict = _sensitive_read(path, cwd, scan.labels, [])
    if not os.path.isdir(path):
        return Review(verdict, target, scan.labels)
    verdict.title = "Claude Code wants to search a folder with sensitive files"
    verdict.facts.append(("Sensitive files", f"{scan.sensitive:,} of {scan.total:,}"))
    if scan.unreadable:
        verdict.facts.append(("Couldn't check", f"{scan.unreadable:,}"))
    search = None
    if scan.clean and isinstance(tool_input.get("pattern"), str):
        verdict.reasons.append("Keep on my Mac searches only the files that passed the check")
        search = CleanSearch(
            tool_input["pattern"], scan.clean, scan.total - len(scan.clean),
            os.path.realpath(cwd), bool(tool_input.get("-i")),
        )
    return Review(verdict, target, scan.labels, clean_search=search)


@dataclass
class CommandScan:
    labels: set[str] = field(default_factory=set)
    sensitive_paths: list[str] = field(default_factory=list)


def _only_inspects_names(command: str) -> bool:
    """True when every step just lists or prints names, so no file contents can come back."""
    if _COMMAND_SUBSTITUTION.search(command) or _AMBIGUOUS_SHELL.search(command):
        return False
    steps = [step.split() for step in _COMMAND_SEPARATORS.split(command) if step.strip()]
    return all(step[0] in _NAME_ONLY_COMMANDS for step in steps if step)


def _named_paths(command: str, cwd: str) -> tuple[list[str], bool]:
    """Return existing paths mentioned anywhere in a command, and whether the list was cut short.

    Matches on the raw text as well as shell words, so a file named inside quotes,
    `--file=x`, or `python -c "open('x')"` is found the same way as a plain argument.
    """
    words = set(_PATH_LIKE.findall(command))
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        words.update(lexer)
    except ValueError:
        pass
    found: dict[str, None] = {}
    truncated = False
    for word in words:
        if word.startswith("-") and "=" not in word:
            continue
        pattern = os.path.join(cwd, os.path.expanduser(word))
        matches = sorted(glob.glob(pattern))[:MAX_GLOB_MATCHES] if _GLOB_CHARS.search(word) else [pattern]
        for match in matches:
            if os.path.exists(match):
                found[os.path.realpath(match)] = None
        if len(found) > MAX_COMMAND_PATHS:
            truncated = True
            break
    return list(found)[:MAX_COMMAND_PATHS], truncated


def _files_in_command(
    command: str, cwd: str, settings: Settings, index: ScanIndex | None
) -> CommandScan:
    """Check every file a shell command names, so combining commands can't hide a read."""
    scan = CommandScan()
    if _only_inspects_names(command):
        return scan
    paths, truncated = _named_paths(command, cwd)
    if truncated:
        scan.labels.add("opaque")
    searches_folders = bool(_FOLDER_READING_COMMANDS.search(command))
    real_cwd = os.path.realpath(cwd)
    for path in paths:
        if os.path.isdir(path):
            if not searches_folders:
                continue
            inside = path == real_cwd or path.startswith(real_cwd + os.sep)
            found = scan_path(path, settings, index) if inside else {"opaque"}
        else:
            found = scan_path(path, settings, index)
        scan.labels |= found
        if found - {"opaque"}:
            scan.sensitive_paths.append(path)
    return scan


def _listed(paths: list[str], cwd: str) -> str:
    shown = [_project_relative(path, cwd) for path in paths[:MAX_LISTED_FILES]]
    extra = len(paths) - len(shown)
    return ", ".join(shown) + (f", and {extra} more" if extra > 0 else "")


def _recursive_search(command: object) -> dict | None:
    """Return Grep-style input for a plain `grep -r` or `rg` command, or None for anything else.

    Only a single command with known flags qualifies, since each extra feature, such as
    `grep -f` or following symlinks with -R, reaches files the folder scan never looked at.
    """
    if not isinstance(command, str) or re.search(r"[$`\n\\]", command):
        return None
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    if len(tokens) < 2 or tokens[0] not in _SEARCH_FLAGS or any(set(t) <= set("();<>|&") for t in tokens):
        return None
    flags = [t for t in tokens[1:] if t.startswith("-")]
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    letters = "".join(flag[1:] for flag in flags)
    if any(flag.startswith("--") or flag == "-" for flag in flags) or not set(letters) <= _SEARCH_FLAGS[tokens[0]]:
        return None
    if (tokens[0] == "grep" and "r" not in letters) or not 1 <= len(operands) <= 2:
        return None
    # Quoting is gone from these tokens, so a wildcard must be visibly quoted in the raw command:
    # unquoted, the shell would expand it into paths this check never sees.
    pattern_is_quoted = f"'{operands[0]}'" in command or f'"{operands[0]}"' in command
    if _SHELL_EXPANSION.search(operands[0]) and not pattern_is_quoted:
        return None
    if len(operands) == 2 and _SHELL_EXPANSION.search(operands[1]):
        return None
    return {"pattern": operands[0], "path": operands[1] if len(operands) == 2 else ".", "-i": "i" in letters}


def _review_bash(
    tool_input: dict, cwd: str, labels: set[str], settings: Settings, index: ScanIndex | None
) -> Review:
    command = tool_input.get("command")
    if isinstance(command, str) and command in _READ_ONLY_GIT:
        return Review(Verdict("allow"), display(command))
    search = _recursive_search(command)
    if search is not None and os.path.exists(_resolve(search["path"], cwd)):
        return _review_grep(search, cwd, labels, settings, index)
    shown = display(command)
    base = review_tool_call("shell", json.dumps({"command": command}), labels, settings)
    if base.decision == "block" or not isinstance(command, str):
        return Review(_named(base), shown)
    scan = _files_in_command(command, cwd, settings, index)
    if scan.labels - {"opaque"}:
        verdict = Verdict(
            "ask", "Claude Code wants to run a command that reads sensitive files",
            [("Command", shown), ("Files", display(_listed(scan.sensitive_paths, cwd)))],
            [_LABEL_REASONS[l] for l in sorted(scan.labels) if l in _LABEL_REASONS] + [CLOUD_WARNING],
        )
        only_one = len(scan.sensitive_paths) == 1 and "opaque" not in scan.labels
        return Review(verdict, shown, scan.labels, scan.sensitive_paths[0] if only_one else None)
    if base.decision == "allow" and "opaque" in scan.labels:
        return Review(_sensitive_read(cwd, cwd, {"opaque"}, []), shown, {"opaque"})
    # Shells can reach a file in more ways than any parser can follow (cd, {a,b}, find -exec, xargs),
    # so a command we can't fully read is warned about based on what its folder holds.
    if base.decision == "ask" and not _only_inspects_names(command):
        nearby = scan_folder(cwd, settings, index)
        if nearby.sensitive:
            count = f"{nearby.sensitive:,} sensitive file{'' if nearby.sensitive == 1 else 's'}"
            verdict = Verdict(
                "ask", "Claude Code wants to run a command that may read sensitive files",
                [("Command", shown), ("In this folder", count)],
                [f"The firewall can't rule out that this command reads them", CLOUD_WARNING],
            )
            return Review(verdict, shown, nearby.labels - {"opaque"})
    return Review(_named(base), shown, scan.labels)


def _is_firewall_file(path: str, settings: Settings) -> bool:
    """True for the firewall's own log, rules or index, under any spelling or hard link."""
    name = _folded(os.path.basename(path))
    for own in (settings.audit_path, settings.policy_path, settings.index_path):
        if not own:
            continue
        real = os.path.realpath(os.path.expanduser(own))
        own_name = _folded(os.path.basename(real))
        if name == own_name or name.startswith(own_name + "-"):
            # Comparing the folder by identity covers aliases that realpath leaves unresolved.
            if _same_file(os.path.dirname(path), os.path.dirname(real)):
                return True
        if any(_same_file(path, real + suffix) for suffix in ("", "-wal", "-shm", "-journal")):
            return True
    return False


def _same_file(first: str, second: str) -> bool:
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def _review_write(tool: str, tool_input: dict, cwd: str, settings: Settings) -> Review:
    # Each tool writes to one field only, so a decoy in the other can't redirect this check.
    raw_path = str(tool_input.get("notebook_path" if tool == "NotebookEdit" else "file_path") or "")
    path = _resolve(raw_path, cwd)
    target = _shown_path(path, cwd)
    if any(canary in json.dumps(tool_input) for canary in settings.canaries):
        return Review(
            Verdict("block", "Blocked: Claude Code tried to write a protected secret",
                    [("File", target)], ["A planted secret appeared in this action"]),
            target,
        )
    # Folded because default macOS volumes treat .GIT and .git as the same directory.
    if _EXECUTABLE_CONFIG.search(_folded(path)) or _is_firewall_file(path, settings):
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


def review_claude_code(
    payload: dict, session_labels: set[str], settings: Settings, index: ScanIndex | None = None
) -> Review:
    """Decide one PreToolUse event. Tools not handled here fall through to the shared policy."""
    tool = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return Review(
            Verdict("block", "Blocked: unreadable action", [("Tool", display(tool))],
                    ["The firewall could not parse this action"]),
            display(tool),
        )
    cwd = str(payload.get("cwd") or os.getcwd())
    settings = replace(settings, agent_workdir=os.path.realpath(cwd))

    if any(canary in text for text in inspectable_text(tool_input) for canary in settings.canaries):
        return Review(
            Verdict("block", "Blocked: Claude Code tried to use a protected secret",
                    [("Tool", display(tool))], ["A planted secret appeared in this action"]),
            display(tool),
        )
    if tool in _NO_DATA_TOOLS:
        return Review(Verdict("allow"), "")
    if tool == "Read":
        return _review_read(tool_input, cwd, session_labels, settings, index)
    if tool == "Grep":
        return _review_grep(tool_input, cwd, session_labels, settings, index)
    if tool == "Bash":
        return _review_bash(tool_input, cwd, session_labels, settings, index)
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
