import json
import pytest
from d810g_engine.protocol import Request, Response, encode_message, decode_message


def test_encode_request():
    req = Request(id=1, method="deflat.detect", params={"address": 0x401000})
    raw = encode_message(req)
    assert b"Content-Length:" in raw
    body = json.loads(raw.split(b"\r\n\r\n", 1)[1])
    assert body["method"] == "deflat.detect"
    assert body["id"] == 1


def test_decode_response():
    resp_data = {
        "id": 1,
        "result": {"patches": [{"address": 0x401000, "bytes": "90"}]},
    }
    raw = encode_message(Response(id=1, result=resp_data["result"]))
    msg = decode_message(raw)
    assert msg.id == 1
    assert msg.result["patches"][0]["address"] == 0x401000


def test_decode_error():
    resp = Response(id=1, error={"code": -1, "message": "unknown method"})
    raw = encode_message(resp)
    msg = decode_message(raw)
    assert msg.error["code"] == -1


def test_roundtrip_request():
    req = Request(id=42, method="mba.simplify", params={"expr": "(x|y)-(x&y)"})
    raw = encode_message(req)
    decoded = decode_message(raw)
    assert isinstance(decoded, Request)
    assert decoded.id == 42
    assert decoded.method == "mba.simplify"
    assert decoded.params["expr"] == "(x|y)-(x&y)"
