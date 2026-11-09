"""Works out what a file holds, reusing the saved scan result while it is still current."""

from __future__ import annotations

import os
import re
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .extract import extract_text
from .policy import classify
from .scan_index import ScanIndex

# Applied only to documents: `tax_utils.py` is code about taxes, `tax_2024.pdf` is a tax return.
_DOCUMENT_SUFFIXES = {
    ".pdf", ".png", ".jpg", ".jpeg", ".heic", ".tiff", ".tif", ".csv", ".txt",
    ".doc", ".docx", ".xls", ".xlsx", ".numbers", ".pages",
}
_NAME_HINTS = {
    "financial": re.compile(r"(^|[^a-z])(tax(es)?|w-?2|1099|bank|statement|payroll|paystub|brokerage)([^a-z]|$)", re.I),
    "health": re.compile(r"(^|[^a-z])(medical|lab[-_ ]?results?|prescriptions?|diagnosis|patient)([^a-z]|$)", re.I),
    "identity": re.compile(r"(^|[^a-z])(passport|ssn|social[-_ ]security|drivers?[-_ ]licen[sc]e)([^a-z]|$)", re.I),
}
_DATALESS_FLAG = getattr(stat_module, "SF_DATALESS", 0x40000000)
_INHERITING_METHODS = {"image_no_text"}


@dataclass
class Inspection:
    labels: set[str]
    method: str
    was_live: bool = False


def _name_labels(path: Path) -> set[str]:
    if path.suffix.lower() not in _DOCUMENT_SUFFIXES:
        return set()
    return {label for label, hint in _NAME_HINTS.items() if hint.search(path.stem)}


def analyze_file(path: Path, status: os.stat_result, settings: Settings) -> Inspection:
    """Read a file now. Cloud placeholders are left alone, since opening one downloads it."""
    hints = _name_labels(path)
    if getattr(status, "st_flags", 0) & _DATALESS_FLAG:
        return Inspection(hints | {"opaque"}, "cloud_placeholder", True)
    extracted = extract_text(path)
    if extracted.text is None:
        return Inspection(hints | {"opaque"}, extracted.method, True)
    labels = hints | classify(extracted.text, settings.canaries)
    return Inspection(labels | ({"opaque"} if extracted.partial else set()), extracted.method, True)


def _with_folder_context(path: Path, result: Inspection, index: ScanIndex) -> Inspection:
    """Give a file we couldn't judge the character of the sensitive folder it sits in."""
    undecided = "opaque" in result.labels or result.method in _INHERITING_METHODS
    if result.labels - {"opaque"} or not undecided:
        return result
    inherited = index.folder_labels(str(path.parent))
    if not inherited:
        return result
    return Inspection((result.labels - {"opaque"}) | inherited | {"inferred"}, result.method, result.was_live)


def inspect_file(
    path: Path, settings: Settings, index: ScanIndex | None = None, allow_live: bool = True
) -> Inspection | None:
    """Return what a file holds, or None if it has no saved result and `allow_live` is False."""
    try:
        status = path.stat()
    except OSError:
        return Inspection({"opaque"}, "unreadable")
    saved = index.get(str(path), status) if index else None
    if saved is not None:
        result = Inspection(saved[0], saved[1])
    elif allow_live:
        result = analyze_file(path, status, settings)
        if index:
            index.put(str(path), status, result.labels, result.method)
    else:
        return None
    return _with_folder_context(path, result, index) if index else result
