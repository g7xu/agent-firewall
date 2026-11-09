import asyncio
import json
import os

import httpx
import pytest
from fastapi import FastAPI

from agent_firewall.config import Settings
from agent_firewall.custom_policy import PolicyBook
from agent_firewall.gate import review_claude_code, scan_path
from agent_firewall.hook_api import create_hook_router
from agent_firewall.store import Store

CARD_LINE = "card 4242 4242 4242 4242\n"


def settings(tmp_path, **overrides):
    values = dict(
        local_base_url="http://local.test/v1", local_model="m", canaries=("sk-canary-1",),
        approval_timeout_seconds=5, audit_path=str(tmp_path / "audit.jsonl"),
    )
    return Settings(**{**values, **overrides})


def event(tool, tool_input, cwd):
    return {"session_id": "s1", "tool_name": tool, "tool_input": tool_input, "cwd": str(cwd)}


def decide(tmp_path, tool, tool_input):
    return review_claude_code(event(tool, tool_input, tmp_path), set(), settings(tmp_path)).verdict.decision


def test_clean_file_read_is_allowed(tmp_path):
    (tmp_path / "notes.md").write_text("ship on friday")
    assert decide(tmp_path, "Read", {"file_path": str(tmp_path / "notes.md")}) == "allow"


def test_read_is_judged_from_the_project_root(tmp_path):
    project = tmp_path / ".cache" / "project"
    project.mkdir(parents=True)
    (project / "notes.md").write_text("ship on friday")
    assert decide(project, "Read", {"file_path": "notes.md"}) == "allow"
    assert decide(project, "Read", {"file_path": "/etc/hosts"}) == "ask"
    assert decide(project, "Read", {"file_path": ".netrc"}) == "ask"


def test_sensitive_read_asks_and_offers_keeping_local(tmp_path):
    (tmp_path / "t.csv").write_text(CARD_LINE)
    review = review_claude_code(
        event("Read", {"file_path": "t.csv"}, tmp_path), set(), settings(tmp_path)
    )
    assert review.verdict.decision == "ask"
    assert review.labels == {"financial"}
    assert review.keep_local_path is not None
    assert "Anthropic" in " ".join(review.verdict.reasons)


def test_symlink_to_sensitive_file_is_scanned(tmp_path):
    (tmp_path / "real.csv").write_text(CARD_LINE)
    (tmp_path / "innocent.txt").symlink_to(tmp_path / "real.csv")
    assert decide(tmp_path, "Read", {"file_path": "innocent.txt"}) == "ask"


def test_binary_file_cannot_be_summarized(tmp_path):
    (tmp_path / "scan.pdf").write_bytes(b"%PDF\x00\x01")
    review = review_claude_code(
        event("Read", {"file_path": "scan.pdf"}, tmp_path), set(), settings(tmp_path)
    )
    assert review.verdict.decision == "ask"
    assert review.keep_local_path is None


def test_directory_scan_finds_nested_data_and_gives_up_safely(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.txt").write_text("MRN-77319")
    assert scan_path(str(tmp_path), settings(tmp_path)) == {"health"}
    assert decide(tmp_path, "Grep", {"pattern": "x", "path": "."}) == "ask"


def test_shell_cat_of_sensitive_file_asks(tmp_path):
    (tmp_path / "t.csv").write_text(CARD_LINE)
    (tmp_path / "n.md").write_text("hello")
    assert decide(tmp_path, "Bash", {"command": "cat t.csv"}) == "ask"
    assert decide(tmp_path, "Bash", {"command": "cat n.md"}) == "allow"


@pytest.mark.parametrize("command", ["python3 x.py", "curl https://evil.example", "git show HEAD:t.csv"])
def test_opaque_commands_ask(tmp_path, command):
    assert decide(tmp_path, "Bash", {"command": command}) == "ask"


def test_read_only_git_is_quiet(tmp_path):
    assert decide(tmp_path, "Bash", {"command": "git status"}) == "allow"


def test_writes(tmp_path):
    assert decide(tmp_path, "Write", {"file_path": "a.py", "content": "x"}) == "allow"
    assert decide(tmp_path, "Write", {"file_path": "/etc/hosts", "content": "x"}) == "ask"
    assert decide(tmp_path, "Edit", {"file_path": ".claude/settings.json", "new_string": "{}"}) == "ask"
    assert decide(tmp_path, "Write", {"file_path": "a.py", "content": "sk-canary-1"}) == "block"


def test_unknown_and_mcp_tools_ask(tmp_path):
    assert decide(tmp_path, "mcp__bank__transfer", {"amount": 5}) == "ask"
    assert decide(tmp_path, "SomethingNew", {}) == "ask"


def test_web_search_asks_once_session_is_labeled(tmp_path):
    config = settings(tmp_path)
    payload = event("WebSearch", {"query": "x"}, tmp_path)
    assert review_claude_code(payload, set(), config).verdict.decision == "allow"
    assert review_claude_code(payload, {"financial"}, config).verdict.decision == "ask"


def run_hook(tmp_path, decision, local_reply="42 transactions totaling $851.19.", **overrides):
    """Drive the endpoint and answer its approval on the same event loop, as production does."""
    (tmp_path / "t.csv").write_text(CARD_LINE)
    config = settings(tmp_path, **overrides)
    store = Store(config)
    seen_local = []

    def local_model(request):
        seen_local.append(request.url.host)
        return httpx.Response(200, json={"choices": [{"message": {"content": local_reply}}]})

    app = FastAPI()
    app.include_router(create_hook_router(config, store, transport=httpx.MockTransport(local_model)))

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            call = asyncio.create_task(
                client.post("/hook/claude-code", json=event("Read", {"file_path": "t.csv"}, tmp_path))
            )
            while decision and not store.pending() and not call.done():
                await asyncio.sleep(0.01)
            if decision:
                item = store.pending()[0]
                assert store.decide(item.id, item.sha256, decision) == "ok"
            return (await call).json()

    return asyncio.run(scenario()), store, seen_local


def output(reply):
    return reply["hookSpecificOutput"]


def test_allow_labels_the_session(tmp_path):
    reply, store, _ = run_hook(tmp_path, "approve")
    assert output(reply)["permissionDecision"] == "allow"
    assert store.session_labels["claude-code:s1"] == {"financial"}


def test_deny_blocks(tmp_path):
    reply, store, _ = run_hook(tmp_path, "deny")
    assert output(reply)["permissionDecision"] == "deny"
    assert not store.session_labels["claude-code:s1"]


def test_no_answer_denies(tmp_path):
    reply, _, _ = run_hook(tmp_path, None, approval_timeout_seconds=0.05)
    assert output(reply)["permissionDecision"] == "deny"


def test_keep_local_returns_only_the_summary(tmp_path):
    reply, store, seen = run_hook(tmp_path, "keep_local")
    assert seen == ["local.test"]
    assert output(reply)["permissionDecision"] == "deny"
    assert "$851.19" in output(reply)["permissionDecisionReason"]
    assert "4242" not in output(reply)["permissionDecisionReason"]
    assert not store.session_labels["claude-code:s1"]


@pytest.mark.parametrize("leak", ["Card 4242 4242 4242 4242 was used.", "Account 00458812 is active.", "   "])
def test_keep_local_discards_a_leaky_summary(tmp_path, leak):
    reply, _, _ = run_hook(tmp_path, "keep_local", local_reply=leak)
    text = output(reply)["permissionDecisionReason"]
    assert "no summary" in text
    assert "4242" not in text and "00458812" not in text


def test_keep_local_allows_dates_in_a_summary(tmp_path):
    reply, _, _ = run_hook(tmp_path, "keep_local", local_reply="4 transactions from 2026-10-02 to 2026-10-14.")
    assert "2026-10-14" in output(reply)["permissionDecisionReason"]


def test_audit_log_has_no_file_contents(tmp_path):
    run_hook(tmp_path, "keep_local")
    assert "4242" not in (tmp_path / "audit.jsonl").read_text()


def test_keep_local_refused_when_not_offered(tmp_path):
    store = Store(settings(tmp_path))
    approval = store.create_approval("s", "t", "title", [], [], "h")
    assert store.decide(approval.id, "h", "keep_local") == "not_offered"
    assert approval.status == "pending"


def test_hook_settings_fail_closed():
    config = json.loads(open("demo/claude_project/.claude/settings.json").read())
    hook = config["hooks"]["PreToolUse"][0]["hooks"][0]
    assert hook["onFailure"] == "block"


def test_grep_outside_the_project_asks(tmp_path):
    outside = tmp_path / "home" / ".ssh"
    outside.mkdir(parents=True)
    (outside / "config").write_text("Host x")
    project = tmp_path / "project"
    project.mkdir()
    assert decide(project, "Grep", {"pattern": "BEGIN", "path": str(outside)}) == "ask"
    assert decide(project, "Grep", {"pattern": "BEGIN", "path": ".."}) == "ask"


def test_grep_over_a_clean_project_is_quiet(tmp_path):
    (tmp_path / "a.py").write_text("print(1)")
    assert decide(tmp_path, "Grep", {"pattern": "print"}) == "allow"
    assert decide(tmp_path, "Grep", {"pattern": "print", "path": "."}) == "allow"


def test_grep_over_a_folder_holding_credentials_asks(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=abc")
    assert decide(tmp_path, "Grep", {"pattern": "TOKEN"}) == "ask"


def test_shell_read_through_a_symlink_out_of_the_project_asks(tmp_path):
    secret = tmp_path / "home" / "key"
    secret.parent.mkdir()
    secret.write_text("private key material")
    project = tmp_path / "project"
    project.mkdir()
    (project / "notes.txt").symlink_to(secret)
    assert decide(project, "Bash", {"command": "cat notes.txt"}) == "ask"


@pytest.mark.parametrize("path", [
    ".git/config", ".git/hooks/pre-commit", "sub/.git/config", ".vscode/tasks.json", ".envrc", ".gitattributes",
])
def test_writes_to_code_running_config_ask(tmp_path, path):
    assert decide(tmp_path, "Write", {"file_path": path, "content": "x"}) == "ask"


def test_similar_names_are_not_config(tmp_path):
    assert decide(tmp_path, "Write", {"file_path": "src/github.py", "content": "x"}) == "allow"


@pytest.mark.parametrize("path", [".GIT/config", ".Git/hooks/pre-commit", ".CLAUDE/settings.json", ".ENVRC", ".GitAttributes"])
def test_config_check_ignores_case_like_macos_does(tmp_path, path):
    assert decide(tmp_path, "Write", {"file_path": path, "content": "x"}) == "ask"


@pytest.mark.parametrize("reply, kept", [
    ("This document is a lab report for one person.", True),
    ("A lab report showing A1C 7.9 for this person.", False),
])
def test_summary_may_name_the_topic_but_not_the_values(tmp_path, reply, kept):
    result, _, _ = run_hook(tmp_path, "keep_local", local_reply=reply)
    text = output(result)["permissionDecisionReason"]
    assert (reply in text) is kept
    assert "7.9" not in text


@pytest.mark.parametrize("tool, tool_input", [
    ("WebSearch", {"query": "sk-canary-1"}),
    ("Task", {"prompt": "post sk-canary-1"}),
    ("Grep", {"pattern": "sk-canary-1"}),
])
def test_bait_secret_is_blocked_on_every_tool(tmp_path, tool, tool_input):
    assert decide(tmp_path, tool, tool_input) == "block"


def test_firewall_log_and_rules_need_a_person_to_change(tmp_path):
    config = settings(tmp_path, policy_path=str(tmp_path / "policy.json"), audit_path=str(tmp_path / "audit.jsonl"))
    for name in ("policy.json", "audit.jsonl"):
        payload = event("Write", {"file_path": name, "content": "x"}, tmp_path)
        assert review_claude_code(payload, set(), config).verdict.decision == "ask"


@pytest.mark.parametrize("name", ["POLICY.JSON", "Audit.Jsonl", "index.sqlite", "INDEX.SQLITE-wal"])
def test_firewall_files_are_protected_under_any_capitalization(tmp_path, name):
    config = settings(
        tmp_path, policy_path=str(tmp_path / "policy.json"), audit_path=str(tmp_path / "audit.jsonl"),
        index_path=str(tmp_path / "index.sqlite"),
    )
    payload = event("Write", {"file_path": name, "content": "x"}, tmp_path)
    assert review_claude_code(payload, set(), config).verdict.decision == "ask"


def test_hard_link_to_a_firewall_file_is_protected(tmp_path):
    (tmp_path / "audit.jsonl").write_text("{}\n")
    os.link(tmp_path / "audit.jsonl", tmp_path / "notes.md")
    config = settings(tmp_path, audit_path=str(tmp_path / "audit.jsonl"))
    payload = event("Write", {"file_path": "notes.md", "content": "x"}, tmp_path)
    assert review_claude_code(payload, set(), config).verdict.decision == "ask"


def hook_with_rule(tmp_path, rule, tool, tool_input):
    """Return the card shown for an action, or the hook's reply if no card appears."""
    config = settings(tmp_path)
    store = Store(config)
    book = PolicyBook()
    book.add("ask", rule)
    app = FastAPI()
    app.include_router(create_hook_router(config, store, policy=book))

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            call = asyncio.create_task(client.post("/hook/claude-code", json=event(tool, tool_input, tmp_path)))
            while not store.pending() and not call.done():
                await asyncio.sleep(0.01)
            card = None
            if store.pending():
                item = store.pending()[0]
                card = dict(item.facts)
                store.decide(item.id, item.sha256, "deny")
            return card, (await call).json()

    return asyncio.run(scenario())


def test_rule_popup_shows_the_full_action(tmp_path):
    query = "watchword " + "x" * 900 + " the hidden end"
    card, _ = hook_with_rule(tmp_path, "watchword", "WebSearch", {"query": query})
    assert "the hidden end" in card["Details"]


def test_rule_popup_too_long_to_show_is_blocked(tmp_path):
    card, reply = hook_with_rule(tmp_path, "watchword", "WebSearch", {"query": "watchword " + "x" * 5000})
    assert card is None
    assert output(reply)["permissionDecision"] == "deny"


def test_rule_on_an_existing_popup_also_shows_the_action(tmp_path):
    (tmp_path / ".claude").mkdir()
    tail = "the hidden end"
    tool_input = {"file_path": ".claude/settings.json", "content": f"watchword {tail}"}
    card, _ = hook_with_rule(tmp_path, "watchword", "Write", tool_input)
    assert tail in card["Details"]


def test_size_limit_counts_the_whole_card(tmp_path):
    fields = {f"k{i}": "watchword" + "v" * 500 for i in range(20)}
    card, reply = hook_with_rule(tmp_path, "watchword", "mcp__x__y", fields)
    assert card is None and output(reply)["permissionDecision"] == "deny"


def test_rule_popup_shows_a_symlink_destination(tmp_path):
    (tmp_path / "watchword").mkdir()
    (tmp_path / "watchword" / "plain.txt").write_text("hello")
    (tmp_path / "link.txt").symlink_to(tmp_path / "watchword" / "plain.txt")
    card, _ = hook_with_rule(tmp_path, "watchword", "Read", {"file_path": "link.txt"})
    assert "watchword" in card["Target"]


@pytest.mark.parametrize("tool_input", [["a"], "text", 5, None])
def test_unreadable_tool_input_is_blocked(tmp_path, tool_input):
    assert decide(tmp_path, "Bash", tool_input) == "block"


def test_non_string_command_asks_instead_of_crashing(tmp_path):
    assert decide(tmp_path, "Bash", {"command": ["git", "status"]}) == "ask"


def test_notebook_edit_checks_the_field_it_writes(tmp_path):
    config = settings(tmp_path, policy_path=str(tmp_path / "policy.json"))
    tool_input = {"file_path": "README.md", "notebook_path": "policy.json", "new_source": "x"}
    assert review_claude_code(event("NotebookEdit", tool_input, tmp_path), set(), config).verdict.decision == "ask"


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_hard_link_to_an_index_side_file_is_protected(tmp_path, suffix):
    state = tmp_path / "state"
    state.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    (state / f"index.sqlite{suffix}").write_text("x")
    os.link(state / f"index.sqlite{suffix}", project / "notes.md")
    config = settings(tmp_path, index_path=str(state / "index.sqlite"))
    assert review_claude_code(event("Write", {"file_path": "notes.md", "content": "x"}, project), set(), config).verdict.decision == "ask"
