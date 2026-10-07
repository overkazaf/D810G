"""Control flow deflattening module."""

from __future__ import annotations
from typing import Any


def register_handlers(server: Any) -> None:
    """Register deflattening handlers on the server."""
    from d810g_engine.deflattener.ollvm import deflat_ollvm
    from d810g_engine.deflattener.tigress import deflat_tigress
    server.register("deflat.run", deflat_ollvm)
    server.register("deflat.tigress", deflat_tigress)
