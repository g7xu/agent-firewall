"""Turns a file into text on this machine, whatever format it is stored in.

The format comes from the file's first bytes rather than its name, so a PDF renamed
to `notes.txt` is still read as a PDF.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT_BYTES = 5_000_000
MAX_OCR_PAGES = 10
MAX_UNZIPPED_BYTES = 20_000_000
_TOOL_TIMEOUT_SECONDS = 30
_OCR_DPI = "150"
_XML_TAG = re.compile(r"<[^>]+>")
_OFFICE_TEXT_PARTS = re.compile(r"^(word/document|word/header\d*|word/footer\d*|xl/sharedStrings|xl/worksheets/.+|ppt/slides/.+)\.xml$")


@dataclass
class Extracted:
    """`text` is None when the file couldn't be read at all, and "" when it holds no text."""

    text: str | None
    method: str
    partial: bool = False


def _is_image(head: bytes) -> bool:
    return (
        head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"II*\x00", b"MM\x00*", b"BM"))
        or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")
        or head[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftypmsf1")
    )


def recognize_text(path: str) -> str | None:
    """Read the words in an image with Apple's on-device Vision framework."""
    try:
        import objc
        import Vision
        from Foundation import NSURL
    except ImportError:
        return None
    with objc.autorelease_pool():
        handler = Vision.VNImageRequestHandler.alloc().initWithURL_options_(
            NSURL.fileURLWithPath_(path), None
        )
        request = Vision.VNRecognizeTextRequest.alloc().init()
        succeeded, _ = handler.performRequests_error_([request], None)
        if not succeeded:
            return None
        lines = [item.topCandidates_(1)[0].string() for item in request.results() or []]
        return "\n".join(str(line) for line in lines)


def _run(command: list[str]) -> subprocess.CompletedProcess | None:
    try:
        result = subprocess.run(command, capture_output=True, timeout=_TOOL_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result if result.returncode == 0 else None


def _pdf_page_count(path: str) -> int | None:
    info = _run(["pdfinfo", path])
    match = re.search(rb"^Pages:\s+(\d+)", info.stdout, re.M) if info else None
    return int(match.group(1)) if match else None


def _read_pdf(path: Path) -> Extracted:
    extracted = _run(["pdftotext", "-layout", str(path), "-"])
    if extracted is None:
        return Extracted(None, "pdf_unreadable")
    text = extracted.stdout.decode("utf-8", "replace")
    if text.strip():
        return Extracted(text, "pdf_text")
    # No text layer means a scan, so its pages have to be read as images.
    with tempfile.TemporaryDirectory(prefix="afw-pdf-") as work:
        rendered = _run([
            "pdftoppm", "-r", _OCR_DPI, "-f", "1", "-l", str(MAX_OCR_PAGES),
            "-png", str(path), f"{work}/page",
        ])
        if rendered is None:
            return Extracted(None, "pdf_unreadable")
        pages = [recognize_text(str(page)) for page in sorted(Path(work).glob("*.png"))]
    if not pages or all(page is None for page in pages):
        return Extracted(None, "pdf_unreadable")
    page_count = _pdf_page_count(str(path))
    partial = page_count is None or page_count > MAX_OCR_PAGES
    return Extracted("\n".join(page or "" for page in pages), "pdf_ocr", partial)


def _read_office(path: Path) -> Extracted:
    try:
        with zipfile.ZipFile(path) as archive:
            parts = [i for i in archive.infolist() if _OFFICE_TEXT_PARTS.match(i.filename)]
            if not parts:
                return Extracted(None, "binary")
            total, chunks, partial = 0, [], False
            for part in parts:
                total += part.file_size
                if total > MAX_UNZIPPED_BYTES:
                    partial = True
                    break
                chunks.append(_XML_TAG.sub(" ", archive.read(part).decode("utf-8", "replace")))
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        return Extracted(None, "office_unreadable")
    return Extracted("\n".join(chunks), "office", partial)


def extract_text(path: Path) -> Extracted:
    try:
        with path.open("rb") as handle:
            head = handle.read(16)
        size = path.stat().st_size
    except OSError:
        return Extracted(None, "unreadable")

    if head.startswith(b"%PDF"):
        return _read_pdf(path)
    if _is_image(head):
        text = recognize_text(str(path))
        if text is None:
            return Extracted(None, "image_unreadable")
        return Extracted(text, "image_ocr" if text.strip() else "image_no_text")
    if head.startswith(b"PK\x03\x04"):
        return _read_office(path)

    if size > MAX_TEXT_BYTES:
        return Extracted(None, "too_large")
    try:
        raw = path.read_bytes()
    except OSError:
        return Extracted(None, "unreadable")
    if b"\x00" in raw:
        return Extracted(None, "binary")
    try:
        return Extracted(raw.decode("utf-8"), "text")
    except UnicodeDecodeError:
        return Extracted(None, "binary")
