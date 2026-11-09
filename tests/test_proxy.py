import json

import httpx
from fastapi.testclient import TestClient

from agent_firewall.config import Settings
from agent_firewall.phone import create_phone_app
from agent_firewall.proxy import create_proxy_app
from agent_firewall.store import Store

CLOUD = "http://cloud.test/v1"
LOCAL = "http://local.test/v1"


def settings(tmp_path, **overrides):
    values = dict(
        cloud_base_url=CLOUD, local_base_url=LOCAL, phone_token="secret",
        approval_timeout_seconds=0.05, canaries=("sk-canary-1",),
        audit_path=str(tmp_path / "audit.jsonl"),
    )
    return Settings(**{**values, **overrides})


def reply(tool=None, arguments="{}"):
    message = {"role": "assistant", "content": "working"}
    if tool:
        message["tool_calls"] = [
            {"id": "c1", "type": "function", "function": {"name": tool, "arguments": arguments}}
        ]
    return {"choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if tool else "stop"}]}


class Upstream:
    def __init__(self, payload=None, local_down=False, cloud_down=False):
        self.hosts = []
        self.payload = payload or reply()
        self.local_down = local_down
        self.cloud_down = cloud_down

    def __call__(self, request):
        self.hosts.append(request.url.host)
        if (request.url.host == "local.test" and self.local_down) or (
            request.url.host == "cloud.test" and self.cloud_down
        ):
            raise httpx.ConnectError("down")
        return httpx.Response(200, json=self.payload)


def client_for(tmp_path, upstream, **overrides):
    config = settings(tmp_path, **overrides)
    store = Store(config)
    app = create_proxy_app(config, store, transport=httpx.MockTransport(upstream))
    return TestClient(app), store


def ask(client, text, session="s1"):
    return client.post(
        "/v1/chat/completions", headers={"x-afw-session": session},
        json={"model": "m", "messages": [{"role": "user", "content": text}]},
    )


def test_clean_request_goes_to_cloud(tmp_path):
    upstream = Upstream()
    client, _ = client_for(tmp_path, upstream)
    assert ask(client, "what time is it").headers["x-afw-route"] == "cloud"
    assert upstream.hosts == ["cloud.test"]


def test_protected_data_goes_local_and_session_stays_local(tmp_path):
    upstream = Upstream()
    client, _ = client_for(tmp_path, upstream)
    ask(client, "account ACCT-123456")
    ask(client, "now something harmless")
    assert upstream.hosts == ["local.test", "local.test"]


def test_protected_data_never_falls_back_to_cloud(tmp_path):
    upstream = Upstream(local_down=True)
    client, _ = client_for(tmp_path, upstream)
    assert ask(client, "MRN-77319 summary").status_code == 503
    assert upstream.hosts == ["local.test"]


def test_cloud_outage_falls_back_to_local(tmp_path):
    upstream = Upstream(cloud_down=True)
    client, _ = client_for(tmp_path, upstream)
    response = ask(client, "plain question")
    assert response.status_code == 200
    assert response.headers["x-afw-route"] == "local"


def test_uninspectable_content_stays_local(tmp_path):
    upstream = Upstream()
    client, _ = client_for(tmp_path, upstream)
    client.post("/v1/chat/completions", json={"messages": [
        {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:x"}}]}
    ]})
    assert upstream.hosts == ["local.test"]


def test_unanswered_approval_strips_the_tool_call(tmp_path):
    upstream = Upstream(reply("transfer_money", json.dumps({"amount": 5})))
    client, _ = client_for(tmp_path, upstream)
    message = ask(client, "pay").json()["choices"][0]["message"]
    assert "tool_calls" not in message
    assert "expired" in message["content"]


def test_canary_in_tool_call_is_stripped_without_asking(tmp_path):
    upstream = Upstream(reply("send_email", json.dumps({"to": "a@b.c", "body": "sk-canary-1"})))
    client, store = client_for(tmp_path, upstream)
    message = ask(client, "send").json()["choices"][0]["message"]
    assert "tool_calls" not in message
    assert store.approvals == {}


def test_allowed_tool_call_passes_through(tmp_path):
    upstream = Upstream(reply("read_inbox"))
    client, _ = client_for(tmp_path, upstream)
    message = ask(client, "inbox").json()["choices"][0]["message"]
    assert message["tool_calls"][0]["function"]["name"] == "read_inbox"


def test_streaming_clients_get_reviewed_output(tmp_path):
    upstream = Upstream(reply("transfer_money", "{}"))
    client, _ = client_for(tmp_path, upstream)
    response = client.post("/v1/chat/completions", json={
        "stream": True, "messages": [{"role": "user", "content": "pay"}],
    })
    assert "transfer_money" not in response.text
    assert response.text.rstrip().endswith("data: [DONE]")


def test_audit_log_contains_no_content(tmp_path):
    upstream = Upstream(reply("send_email", json.dumps({"to": "a@b.c", "body": "topsecretbody"})))
    client, _ = client_for(tmp_path, upstream)
    ask(client, "ACCT-123456 please")
    audit = (tmp_path / "audit.jsonl").read_text()
    assert "ACCT-123456" not in audit
    assert "topsecretbody" not in audit


def test_decide_rejects_tampering_replay_and_expiry(tmp_path):
    store = Store(settings(tmp_path, approval_timeout_seconds=30))
    approval = store.create_approval("s", "t", "title", [], [], "good-hash")
    assert store.decide(approval.id, "other-hash", "approve") == "hash_mismatch"
    assert store.decide(approval.id, "good-hash", "approve") == "ok"
    assert store.decide(approval.id, "good-hash", "approve") == "already_decided"

    stale = store.create_approval("s", "t", "title", [], [], "h2")
    stale.expires_at = 0
    assert store.decide(stale.id, "h2", "approve") == "expired"
    assert stale.status == "expired"


def test_phone_api_requires_token(tmp_path):
    config = settings(tmp_path)
    client = TestClient(create_phone_app(config, Store(config)))
    assert client.get("/api/pending").status_code == 403
    assert client.get("/api/pending", params={"t": "wrong"}).status_code == 403
    assert client.get("/api/pending", params={"t": "secret"}).status_code == 200
