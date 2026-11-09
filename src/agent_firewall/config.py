from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from dotenv import load_dotenv


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    cloud_base_url: str = ""
    cloud_api_key: str = ""
    cloud_model: str = ""
    local_base_url: str = "http://127.0.0.1:11434/v1"
    local_model: str = ""
    proxy_port: int = 8787
    phone_port: int = 8788
    phone_token: str = ""
    approval_timeout_seconds: float = 90.0
    allowed_hosts: tuple[str, ...] = ()
    known_recipients: tuple[str, ...] = ()
    canaries: tuple[str, ...] = ()
    audit_path: str = "audit.jsonl"
    agent_workdir: str = ""
    popup: str = "off"
    worst_case_model: str = ""
    scan_roots: tuple[str, ...] = ()
    index_path: str = ""
    policy_path: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        return cls(
            cloud_base_url=os.environ.get("CLOUD_BASE_URL", "").rstrip("/"),
            cloud_api_key=os.environ.get("CLOUD_API_KEY", ""),
            cloud_model=os.environ.get("CLOUD_MODEL", ""),
            local_base_url=os.environ.get("LOCAL_BASE_URL", cls.local_base_url).rstrip("/"),
            local_model=os.environ.get("LOCAL_MODEL", ""),
            proxy_port=int(os.environ.get("PROXY_PORT", cls.proxy_port)),
            phone_port=int(os.environ.get("PHONE_PORT", cls.phone_port)),
            phone_token=os.environ.get("PHONE_TOKEN") or secrets.token_urlsafe(16),
            approval_timeout_seconds=float(
                os.environ.get("APPROVAL_TIMEOUT_SECONDS", cls.approval_timeout_seconds)
            ),
            allowed_hosts=_csv("ALLOWED_HOSTS"),
            known_recipients=_csv("KNOWN_RECIPIENTS"),
            canaries=_csv("CANARIES"),
            audit_path=os.environ.get("AUDIT_PATH", cls.audit_path),
            agent_workdir=os.environ.get("AGENT_WORKDIR", ""),
            popup=os.environ.get("POPUP", "mac"),
            worst_case_model=os.environ.get("WORST_CASE_MODEL", ""),
            scan_roots=_csv("SCAN_ROOTS", "~/Documents,~/Desktop,~/Downloads"),
            index_path=os.environ.get("INDEX_PATH", "~/.agent-firewall/index.sqlite"),
            policy_path=os.environ.get("POLICY_PATH", "~/.agent-firewall/policy.json"),
        )
