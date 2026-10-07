"""Bogus Control Flow detection and removal module."""

from __future__ import annotations
from typing import Any


def register_handlers(server: Any) -> None:
    """Register BCF detection handlers on the server."""
    from d810g_engine.bcf.detector import detect_and_remove_bcf
    server.register("bcf.run", detect_and_remove_bcf)
