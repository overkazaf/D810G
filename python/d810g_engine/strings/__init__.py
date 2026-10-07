"""OLLVM string decryption module."""

from __future__ import annotations
from typing import Any


def register_handlers(server: Any) -> None:
    """Register string decryption handlers on the server."""
    from d810g_engine.strings.decryptor import decrypt_strings
    server.register("strings.decrypt", decrypt_strings)
