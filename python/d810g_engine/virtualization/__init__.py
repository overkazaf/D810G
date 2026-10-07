"""Tigress VM devirtualization module."""

from __future__ import annotations
from typing import Any


def register_handlers(server: Any) -> None:
    """Register VM analysis handlers on the server."""
    from d810g_engine.virtualization.analyzer import analyze_vm
    from d810g_engine.virtualization.tracer import trace_vm
    server.register("vm.analyze", analyze_vm)
    server.register("vm.trace", trace_vm)
