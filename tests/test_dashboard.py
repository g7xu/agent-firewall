import json

import pytest
from fastapi.testclient import TestClient

from agent_firewall import dashboard
from agent_firewall.config import Settings
from agent_firewall.custom_policy import PolicyBook, searchable_text
from agent_firewall.phone import create_phone_app
from agent_firewall.policy import Verdict
from agent_firewall.store import Store


def write_audit(path, events):
    path.write_text("".join(json.dumps(e) + "\n" for e in events) + "not json\n")


EVENTS = [
    {"ts": 1, "kind": "tool", "agent": "claude-code", "tool": "Read", "target": "a.md", "decision": "allow", "labels": [], "sha256": "a"},
    {"ts": 2, "kind": "tool", "agent": "claude-code", "tool": "Read", "target": "t.csv", "decision": "ask", "labels": ["financial"], "sha256": "b"},
    {"ts": 3, "kind": "approval", "agent": "claude-code", "tool": "Read", "target": "t.csv", "status": "denied", "sha256": "b"},
    {"ts": 4, "kind": "tool", "agent": "claude-code", "tool": "Read", "target": "t.csv", "decision": "ask", "labels": ["financial"], "sha256": "c"},
    {"ts": 5, "kind": "approval", "agent": "claude-code", "tool": "Read", "target": "t.csv", "status": "kept_local", "sha256": "c"},
    {"ts": 6, "kind": "tool", "agent": "claude-code", "tool": "Bash", "target": "python3 x.py", "decision": "ask", "labels": [],
     "reasons": ["The firewall can't tell what this command does"], "sha256": "d"},
    {"ts": 7, "kind": "approval", "agent": "claude-code", "tool": "Bash", "target": "python3 x.py", "status": "approved", "sha256": "d"},
    {"ts": 8, "kind": "tool", "tool": "send_email", "target": "x", "decision": "block", "sha256": "e"},
    {"ts": 9, "kind": "route", "route": "local", "why": "protected: health", "labels": ["health"]},
    {"ts": 10, "kind": "route", "route": "cloud", "why": "no protected data", "labels": []},
]


def counts_for(tmp_path, files=()):
    settings = Settings(audit_path=str(tmp_path / "a.jsonl"))
    write_audit(tmp_path / "a.jsonl", EVENTS)
    return dashboard.category_counts(dashboard.all_items(settings, list(files)))


def test_activity_lands_in_the_right_categories(tmp_path):
    counts = counts_for(tmp_path)
    assert counts["denied"] == 2
    assert counts["local"] == 2
    assert counts["cloud"] == 3
    assert counts["uncertain"] == 1
    assert counts["sensitive"] == 3


def test_an_answered_question_is_listed_once(tmp_path):
    settings = Settings(audit_path=str(tmp_path / "a.jsonl"))
    write_audit(tmp_path / "a.jsonl", EVENTS)
    items = dashboard.all_items(settings, [])
    assert [i["state"] for i in items if i["target"] == "t.csv"] == ["kept_local", "denied"]


def test_flagged_files_are_listed(tmp_path):
    files = [("/x/card.pdf", ["financial"], "pdf_text", 11.0), ("/x/blob.bin", ["opaque"], "binary", 12.0)]
    counts = counts_for(tmp_path, files)
    assert counts["sensitive"] == 4 and counts["uncertain"] == 2


def test_selecting_and_searching(tmp_path):
    settings = Settings(audit_path=str(tmp_path / "a.jsonl"))
    write_audit(tmp_path / "a.jsonl", EVENTS)
    items = dashboard.all_items(settings, [])
    assert dashboard.select_items(items, "denied", "")["total"] == 2
    assert dashboard.select_items(items, "all", "PYTHON3")["total"] == 1


def test_missing_audit_log_is_empty():
    assert dashboard.read_audit("/nonexistent/a.jsonl") == []


MAC = ("127.0.0.1", 5000)
TOKEN = {"t": "secret"}


def phone(tmp_path, client=MAC, book=None):
    config = Settings(phone_token="secret", audit_path=str(tmp_path / "a.jsonl"), allowed_hosts=("a.test",), canaries=("sk-x",))
    write_audit(tmp_path / "a.jsonl", EVENTS)
    return TestClient(create_phone_app(config, Store(config), None, book), client=client, base_url="http://127.0.0.1:8788")


@pytest.mark.parametrize("method, path", [
    ("get", "/api/overview"), ("get", "/api/items"), ("get", "/api/policy"),
    ("post", "/api/policy/entries"), ("delete", "/api/policy/entries/x"), ("get", "/api/stats"),
])
def test_private_routes_refuse_other_devices_and_bad_tokens(tmp_path, method, path):
    from_phone = phone(tmp_path, client=("192.168.1.9", 5000))
    assert getattr(from_phone, method)(path, params=TOKEN).status_code == 403
    assert getattr(phone(tmp_path), method)(path, params={"t": "wrong"}).status_code == 403


def test_overview_and_items(tmp_path):
    client = phone(tmp_path)
    assert client.get("/api/overview", params=TOKEN).json()["counts"]["denied"] == 2
    body = client.get("/api/items", params={**TOKEN, "category": "local"}).json()
    assert body["total"] == 2
    assert client.get("/api/items", params={**TOKEN, "category": "nope"}).status_code == 400


def test_policy_view_never_reveals_bait_values(tmp_path):
    body = phone(tmp_path).get("/api/policy", params=TOKEN)
    assert body.json()["settings"]["bait_secrets"] == 1
    assert "sk-x" not in body.text


def test_entries_can_be_added_listed_and_deleted(tmp_path):
    client = phone(tmp_path)
    made = client.post("/api/policy/entries", params=TOKEN, json={"kind": "block", "text": "paypal.com"}).json()
    assert client.get("/api/policy", params=TOKEN).json()["entries"][0]["text"] == "paypal.com"
    assert client.delete(f"/api/policy/entries/{made['id']}", params=TOKEN).status_code == 200
    assert client.get("/api/policy", params=TOKEN).json()["entries"] == []


@pytest.mark.parametrize("entry", [
    {"kind": "allow", "text": "everything"}, {"kind": "block", "text": ""}, {"kind": "block", "text": "x"},
    {"kind": "idea", "text": "y" * 501},
])
def test_bad_entries_are_refused(tmp_path, entry):
    assert phone(tmp_path).post("/api/policy/entries", params=TOKEN, json=entry).status_code == 400


def test_entries_survive_a_restart(tmp_path):
    path = str(tmp_path / "state" / "policy.json")
    PolicyBook(path).add("idea", "想法 one")
    assert PolicyBook(path).entries[0]["text"] == "想法 one"
    assert (tmp_path / "state" / "policy.json").stat().st_mode & 0o077 == 0


def test_corrupt_policy_file_is_kept_aside(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{broken")
    assert PolicyBook(str(path)).entries == []
    assert (tmp_path / "policy.corrupt").exists()


ALLOW, ASK, BLOCK = "allow", "ask", "block"


def book_with(kind, text):
    book = PolicyBook()
    book.add(kind, text)
    return book


def applied(book, decision, haystack="post to PayPal.com"):
    verdict = Verdict(decision, "Agent wants to contact a website", [], [])
    return book.apply(verdict, haystack, "Claude Code", [("Tool", "x")])


def test_ask_rule_turns_allow_into_a_popup():
    result = applied(book_with("ask", "paypal.com"), ALLOW)
    assert result.decision == ASK and "paypal.com" in result.reasons[0]


def test_block_rule_stops_allowed_and_asked_actions():
    assert applied(book_with("block", "paypal.com"), ALLOW).decision == BLOCK
    assert applied(book_with("block", "paypal.com"), ASK).decision == BLOCK


def test_ask_rule_does_not_change_a_block():
    assert applied(book_with("ask", "paypal.com"), BLOCK).decision == BLOCK


@pytest.mark.parametrize("decision", [ALLOW, ASK, BLOCK])
def test_ideas_and_unmatched_rules_change_nothing(decision):
    assert applied(book_with("idea", "paypal.com"), decision).decision == decision
    assert applied(book_with("block", "stripe.com"), decision).decision == decision


def test_strictest_matching_rule_wins():
    book = book_with("block", "paypal")
    book.add("ask", "paypal.com")
    assert applied(book, ALLOW).decision == BLOCK


@pytest.mark.parametrize("parts", [
    ("http_post", '{"url": "https://paypal\\u002ecom/pay"}'),
    ("http_post", {"nested": ["x", {"url": "https://PayPal.com/pay"}]}),
    ("https://paypal.com", "{not json"),
])
def test_rules_see_through_json_escapes(parts):
    assert applied(book_with("block", "paypal.com"), ALLOW, searchable_text(*parts)).decision == BLOCK


def test_rule_with_quotes_matches_decoded_text():
    haystack = searchable_text("shell", {"command": 'say "hello there"'})
    assert applied(book_with("block", '"hello there"'), ALLOW, haystack).decision == BLOCK


def test_private_routes_refuse_a_forwarded_host_name(tmp_path):
    client = phone(tmp_path)
    assert client.get("/api/policy", params=TOKEN, headers={"host": "evil.example"}).status_code == 403


def test_overview_counts_activity_without_flagged_files(tmp_path):
    assert phone(tmp_path).get("/api/overview", params=TOKEN).json()["activity"] == 7


def test_a_repeat_of_an_answered_action_stays_visible(tmp_path):
    settings = Settings(audit_path=str(tmp_path / "a.jsonl"))
    repeat = {"kind": "tool", "tool": "Bash", "target": "x", "decision": "ask", "sha256": "same"}
    write_audit(tmp_path / "a.jsonl", [
        {**repeat, "ts": 1}, {"ts": 2, "kind": "approval", "tool": "Bash", "target": "x", "status": "approved", "sha256": "same"},
        {**repeat, "ts": 3},
    ])
    assert [i["state"] for i in dashboard.all_items(settings, [], {"same"})] == ["ask", "approved"]
    assert [i["state"] for i in dashboard.all_items(settings, [])] == ["unanswered", "approved"]


def test_tools_that_return_no_data_are_not_counted_as_cloud(tmp_path):
    settings = Settings(audit_path=str(tmp_path / "a.jsonl"))
    write_audit(tmp_path / "a.jsonl", [{"ts": 1, "kind": "tool", "agent": "claude-code", "tool": "TodoWrite", "decision": "allow"}])
    assert "cloud" not in dashboard.all_items(settings, [])[0]["categories"]


def test_damaged_log_lines_do_not_break_the_page(tmp_path):
    settings = Settings(audit_path=str(tmp_path / "a.jsonl"))
    write_audit(tmp_path / "a.jsonl", [{"ts": 1, "kind": "tool", "tool": "x", "decision": "ask", "labels": 5, "reasons": "bad"}])
    assert dashboard.all_items(settings, [])[0]["labels"] == []


@pytest.mark.parametrize("text", ["paypal.com", "PAYPAL.COM", "pay​pal.com", "pay­pal.com"])
def test_rules_see_through_case_and_invisible_characters(text):
    assert applied(book_with("block", "paypal.com"), ALLOW, f"go to {text}").decision == BLOCK


def test_rules_ignore_extra_spaces():
    assert applied(book_with("ask", "cat notes.txt"), ALLOW, "cat   notes.txt").decision == ASK


def test_block_message_does_not_reveal_the_rule():
    assert "paypal" not in applied(book_with("block", "paypal.com"), ALLOW).title


def test_concurrent_saves_leave_a_valid_file(tmp_path):
    book = PolicyBook(str(tmp_path / "policy.json"))
    for i in range(20):
        book.add("idea", f"idea {i}")
    assert len(json.loads((tmp_path / "policy.json").read_text())) == 20
    assert (tmp_path / "policy.json").stat().st_mode & 0o077 == 0
    assert [p.name for p in tmp_path.iterdir()] == ["policy.json"]


@pytest.mark.parametrize("gap", ["\t", "\n", "\r\n", "  ", " "])
def test_rules_treat_every_kind_of_gap_as_a_space(gap):
    assert applied(book_with("ask", "git push"), ALLOW, f"git{gap}push origin").decision == ASK


@pytest.mark.parametrize("gap", ["\t", "\n", "\r\n"])
def test_rules_catch_control_characters_inside_a_url(gap):
    assert applied(book_with("block", "paypal.com"), ALLOW, f"https://pay{gap}pal.com/x").decision == BLOCK


@pytest.mark.parametrize("hidden", ["͏", "️", "︀", "᠋", "\U000e0100", "⁥"])
def test_rules_see_through_other_invisible_characters(hidden):
    assert applied(book_with("block", "paypal.com"), ALLOW, f"pay{hidden}pal.com").decision == BLOCK


@pytest.mark.parametrize("filler", ["ㅤ", "ﾠ", "ᅟ", "⠀"])
def test_blank_looking_characters_count_as_a_gap(filler):
    assert applied(book_with("ask", "git push"), ALLOW, f"git{filler}push").decision == ASK


def test_shell_line_continuation_counts_as_a_gap():
    assert applied(book_with("ask", "git push"), ALLOW, "git \\\n push origin").decision == ASK


def test_argv_style_lists_match_in_order():
    assert applied(book_with("block", "git push"), ALLOW, searchable_text({"argv": ["git", "push", "origin"]})).decision == BLOCK
