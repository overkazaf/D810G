"""JSON-RPC server over stdio -- dispatches to registered handlers."""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any, Callable

from d810g_engine.protocol import Request, Response


Handler = Callable[[dict[str, Any]], Any]


class Server:
    def __init__(self):
        self._handlers: dict[str, Handler] = {}
        self._running = False

    def register(self, method: str, handler: Handler) -> None:
        self._handlers[method] = handler

    def _read_message(self) -> Request | None:
        header_line = sys.stdin.buffer.readline()
        if not header_line:
            return None
        while True:
            line = sys.stdin.buffer.readline()
            if line == b"\r\n" or line == b"\n":
                break
            if not line:
                return None
        content_length = int(header_line.split(b":")[1].strip())
        body = sys.stdin.buffer.read(content_length)
        data = json.loads(body)
        return Request(id=data.get("id", 0), method=data["method"], params=data.get("params", {}))

    def _write_response(self, resp: Response) -> None:
        body = {"id": resp.id}
        if resp.error is not None:
            body["error"] = resp.error
        else:
            body["result"] = resp.result
        payload = json.dumps(body).encode("utf-8")
        sys.stdout.buffer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()

    def serve(self) -> None:
        self._running = True
        while self._running:
            req = self._read_message()
            if req is None:
                break
            if req.method == "shutdown":
                self._write_response(Response(id=req.id, result={"status": "ok"}))
                break
            handler = self._handlers.get(req.method)
            if handler is None:
                self._write_response(Response(
                    id=req.id,
                    error={"code": -1, "message": f"unknown method: {req.method}"},
                ))
                continue
            try:
                result = handler(req.params)
                self._write_response(Response(id=req.id, result=result))
            except Exception as e:
                self._write_response(Response(
                    id=req.id,
                    error={"code": -2, "message": str(e), "traceback": traceback.format_exc()},
                ))


def main() -> int:
    from d810g_engine.deflattener import register_handlers as register_deflat
    from d810g_engine.mba import register_handlers as register_mba
    from d810g_engine.opaque import register_handlers as register_opaque
    from d810g_engine.bcf import register_handlers as register_bcf
    from d810g_engine.strings import register_handlers as register_strings
    from d810g_engine.virtualization import register_handlers as register_vm
    from d810g_engine.dce import register_handlers as register_dce

    server = Server()
    register_deflat(server)
    register_mba(server)
    register_opaque(server)
    register_bcf(server)
    register_strings(server)
    register_vm(server)
    register_dce(server)
    server.serve()
    return 0
