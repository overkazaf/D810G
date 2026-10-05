"""OLLVM control flow flattening recovery."""

from __future__ import annotations
from typing import Any

from d810g_engine.deflattener.detector import detect_cff_pattern
from d810g_engine.deflattener.symbolic import solve_state_transitions, patch_control_flow


def deflat_ollvm(params: dict[str, Any]) -> dict[str, Any]:
    """Main entry: detect CFF, solve states, generate patches."""
    blocks = params["blocks"]
    binary_bytes = bytes.fromhex(params["binary_hex"])
    arch = params.get("arch", "x86_64")

    pattern = detect_cff_pattern(blocks)
    if pattern is None:
        return {"status": "no_cff_detected", "patches": []}

    transitions = solve_state_transitions(
        binary_bytes=binary_bytes,
        arch=arch,
        dispatcher_addr=pattern["dispatcher"],
        state_var_offset=params.get("state_var_offset", 0),
        state_var_size=params.get("state_var_size", 4),
        case_blocks=pattern["case_blocks"],
    )

    patches = patch_control_flow(
        binary_bytes=bytearray(binary_bytes),
        arch=arch,
        transitions=transitions,
        dispatcher_addr=pattern["dispatcher"],
    )

    return {
        "status": "deobfuscated",
        "pattern": pattern,
        "transitions": transitions,
        "patches": [
            {"address": p["address"], "bytes": p["patch_bytes"].hex()}
            for p in patches
        ],
    }
