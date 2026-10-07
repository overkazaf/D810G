"""Dead Code Elimination module."""

from __future__ import annotations
from typing import Any


def register_handlers(server: Any) -> None:
    """Register DCE handlers on the server."""
    from d810g_engine.dce.eliminator import eliminate_dead_code
    server.register("dce.run", eliminate_dead_code)
