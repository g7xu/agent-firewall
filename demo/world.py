"""Fake outside world for demos: a scripted model and an attacker's collection server.

The scripted model obeys the current case's steps, standing in for a model that
has fallen for the injection. It measures the firewall's plumbing, not how
often a real model gets tricked.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

import uvicorn
from fastapi import FastAPI, Request

WORLD_PORT = 9100

app = FastAPI(title="Demo world")
state: dict = {"script": [], "cloud_saw": [], "local_saw": [], "sink": []}


def _substitute(value, last: str):
    if not isinstance(value, str):
        return value
    half = last[: len(last) // 2]
    encoded = base64.b64encode(last.encode()).decode()
    return (
        value.replace("$B64LAST", encoded).replace("$HALFLAST", half).replace("$LAST", last)
    )


def _scripted_reply(messages: list[dict], served_by: str) -> dict:
    tool_messages = [m for m in messages if m.get("role") == "tool"]
    step = len(tool_messages)
    message: dict = {"role": "assistant", "content": ""}
    finish_reason = "stop"
    if step < len(state["script"]):
        name, args = state["script"][step]
        last = str(tool_messages[-1].get("content", "")) if tool_messages else ""
        filled = {key: _substitute(value, last) for key, value in args.items()}
        message["tool_calls"] = [{
            "id": f"call_{uuid.uuid4().hex[:8]}", "type": "function",
            "function": {"name": name, "arguments": json.dumps(filled)},
        }]
        finish_reason = "tool_calls"
    else:
        message["content"] = f"Done. (served by {served_by})"
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:8]}", "object": "chat.completion",
        "created": int(time.time()), "model": served_by,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }


@app.post("/cloud/v1/chat/completions")
async def cloud(request: Request) -> dict:
    body = await request.json()
    state["cloud_saw"].append(json.dumps(body["messages"]))
    return _scripted_reply(body["messages"], "mock-cloud")


@app.post("/local/v1/chat/completions")
async def local(request: Request) -> dict:
    body = await request.json()
    state["local_saw"].append(json.dumps(body["messages"]))
    return _scripted_reply(body["messages"], "mock-local")


@app.post("/sink")
async def sink(request: Request) -> dict:
    state["sink"].append(await request.json())
    return {"ok": True}


@app.post("/reset")
async def reset(request: Request) -> dict:
    payload = await request.json()
    state.update(script=payload.get("script", []), cloud_saw=[], local_saw=[], sink=[])
    return {"ok": True}


@app.get("/state")
def read_state() -> dict:
    return state


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=WORLD_PORT, log_level="warning")
