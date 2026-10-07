"""Multi-pass deobfuscation pipeline."""

from __future__ import annotations
from typing import Any


def register_handlers(server: Any) -> None:
    """Register pipeline handlers on the server."""
    from d810g_engine.pipeline.orchestrator import run_pipeline
    server.register("pipeline.run", run_pipeline)
