"""Runs a folder search over only the files that passed the scan."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from .config import Settings
from .policy import classify

MAX_RESULT_CHARS = 8000
_CHUNK_FILES = 200
_TIMEOUT_SECONDS = 20
_NO_MATCH = 1


@dataclass
class CleanSearch:
    pattern: str
    files: list[str]
    left_out: int
    root: str
    ignore_case: bool = False


def run_clean_search(search: CleanSearch, settings: Settings) -> str:
    """Return matching lines. `grep` runs out of process so a costly pattern can't stall the firewall."""
    base = ["grep", "-E", "-n", "-I", "-H"] + (["-i"] if search.ignore_case else [])
    lines: list[str] = []
    used = 0
    for start in range(0, len(search.files), _CHUNK_FILES):
        chunk = search.files[start:start + _CHUNK_FILES]
        try:
            result = subprocess.run(
                [*base, "-e", search.pattern, "--", *chunk], capture_output=True, timeout=_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "\n".join(lines + ["(search stopped early)"])
        if result.returncode not in (0, _NO_MATCH):
            continue
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            if classify(line, settings.canaries):
                continue
            shown = line[len(search.root) + 1:] if line.startswith(search.root + os.sep) else line
            used += len(shown) + 1
            if used > MAX_RESULT_CHARS:
                return "\n".join(lines + ["(more matches not shown)"])
            lines.append(shown)
    return "\n".join(lines)
