"""JSON-RPC-like protocol over stdio with Content-Length framing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Request:
    """Incoming JSON-RPC request."""

    method: str
    id: int = 0
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Response:
    """Outgoing JSON-RPC response."""

    id: int = 0
    result: Any = None
    error: dict[str, Any] | None = None


def encode_message(msg: Request | Response) -> bytes:
    """Serialize a Request or Response to Content-Length-framed bytes."""
    if isinstance(msg, Request):
        body = {"id": msg.id, "method": msg.method, "params": msg.params}
    else:
        body = {"id": msg.id}
        if msg.error is not None:
            body["error"] = msg.error
        else:
            body["result"] = msg.result
    payload = json.dumps(body).encode("utf-8")
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    return header + payload


def decode_message(raw: bytes) -> Request | Response:
    """Deserialize Content-Length-framed bytes into a Request or Response."""
    _header, body_bytes = raw.split(b"\r\n\r\n", 1)
    body = json.loads(body_bytes)
    if "method" in body:
        return Request(id=body.get("id", 0), method=body["method"], params=body.get("params", {}))
    return Response(id=body.get("id", 0), result=body.get("result"), error=body.get("error"))
