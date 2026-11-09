"""Minimal tool-using agent for demos.

Its tools never touch the real system: outbound actions land in the demo
world's sink, shell commands are recorded instead of run, and files come only
from `demo/fake_data`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx

from demo.world import WORLD_PORT

DATA_DIR = Path(__file__).parent / "fake_data"
CASES_PATH = Path(__file__).parent / "cases.json"
WORLD_URL = f"http://127.0.0.1:{WORLD_PORT}"
GUARD_URL = "http://127.0.0.1:8787/v1"
MAX_TURNS = 10
REQUEST_TIMEOUT_SECONDS = 150

_TOOL_NAMES = [
    ("read_inbox", {}),
    ("read_file", {"path": "string"}),
    ("http_post", {"url": "string", "data": "string"}),
    ("send_email", {"to": "string", "subject": "string", "body": "string"}),
    ("shell", {"command": "string"}),
    ("transfer_money", {"to_account": "string", "amount_usd": "number"}),
    ("add_payee", {"name": "string", "account": "string"}),
    ("create_refund", {"charge": "string", "amount_usd": "number"}),
    ("update_prescription", {"drug": "string", "dose_mg": "number"}),
    ("share_record", {"recipient": "string", "record": "string"}),
    ("export_all_contacts", {"destination": "string"}),
]
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": name,
            "description": f"Demo tool: {name.replace('_', ' ')}.",
            "parameters": {
                "type": "object",
                "properties": {key: {"type": kind} for key, kind in params.items()},
            },
        },
    }
    for name, params in _TOOL_NAMES
]


def load_cases() -> list[dict]:
    return json.loads(CASES_PATH.read_text())


def execute(name: str, args: dict, case: dict, world_url: str = WORLD_URL) -> str:
    if name == "read_inbox":
        return case["inbox"]
    if name == "read_file":
        path = (DATA_DIR / str(args.get("path", ""))).resolve()
        if not path.is_relative_to(DATA_DIR.resolve()) or not path.is_file():
            return "error: file not found"
        return path.read_text()
    httpx.post(f"{world_url}/sink", json={"tool": name, "args": args})
    return "ok"


def run_case(
    case: dict, base_url: str, session: str, model: str = "demo", api_key: str = "",
    verbose: bool = False, world_url: str = WORLD_URL,
) -> dict:
    messages: list[dict] = [
        {"role": "system", "content": "You are a personal assistant. Use tools when needed."},
        {"role": "user", "content": case["task"]},
    ]
    headers = {"x-afw-session": session}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    for _ in range(MAX_TURNS):
        response = httpx.post(
            f"{base_url}/chat/completions", headers=headers, timeout=REQUEST_TIMEOUT_SECONDS,
            json={"model": model, "messages": messages, "tools": TOOLS},
        )
        response.raise_for_status()
        message = response.json()["choices"][0]["message"]
        messages.append(message)
        if verbose:
            route = response.headers.get("x-afw-route", "no firewall")
            print(f"[{route}] {message.get('content') or '(tool call)'}")
        calls = message.get("tool_calls")
        if not calls:
            return {"final": message.get("content", "")}
        for call in calls:
            name = call["function"]["name"]
            args = json.loads(call["function"].get("arguments") or "{}")
            if verbose:
                print(f"  -> {name} {json.dumps(args)[:120]}")
            messages.append({
                "role": "tool", "tool_call_id": call["id"],
                "content": execute(name, args, case, world_url),
            })
    return {"final": "(turn limit reached)"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one demo case.")
    parser.add_argument("--case", default="A01")
    parser.add_argument("--no-firewall", action="store_true")
    args = parser.parse_args()

    case = next(c for c in load_cases() if c["id"] == args.case)
    httpx.post(f"{WORLD_URL}/reset", json={"script": case["script"]})
    base_url = f"{WORLD_URL}/cloud/v1" if args.no_firewall else GUARD_URL
    print(f"Case {case['id']}: {case['name']}\n")
    run_case(case, base_url, session=f"live-{case['id']}", verbose=True)
    state = httpx.get(f"{WORLD_URL}/state").json()
    print(f"\nActions that left the machine: {len(state['sink'])}")
    for record in state["sink"]:
        print(f"  {json.dumps(record)[:200]}")


if __name__ == "__main__":
    main()
