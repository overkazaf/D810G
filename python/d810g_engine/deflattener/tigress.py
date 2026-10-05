"""Tigress control flow flattening recovery."""

from __future__ import annotations
from typing import Any

from d810g_engine.deflattener.detector import detect_cff_pattern


def detect_tigress_pattern(blocks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Detect Tigress-style CFF patterns.

    Tigress variants:
    1. Indirect jump table: dispatcher uses jmp [table + state*8]
    2. If-chain: dispatcher uses sequential if/else comparisons
    3. Nested loops: multiple dispatcher layers
    """
    # Pattern 1: Indirect jump with jump table
    for block in blocks:
        if block.get("has_indirect_jump") and block.get("jump_table"):
            table = block["jump_table"]
            back_edges = sum(
                1 for other in blocks
                if other["addr"] != block["addr"]
                and block["addr"] in other.get("succs", [])
            )
            if back_edges >= 2:
                case_blocks = [
                    other["addr"] for other in blocks
                    if other["addr"] != block["addr"]
                    and block["addr"] in other.get("succs", [])
                    and "state_update" in other
                ]
                if len(case_blocks) >= 2:
                    return {
                        "type": "tigress_indirect",
                        "dispatcher": block["addr"],
                        "case_blocks": case_blocks,
                        "jump_table": table,
                        "num_cases": len(table),
                    }

    # Pattern 2: If-chain dispatcher
    # Characterized by a block with exactly 2 successors where one leads
    # to another comparison block forming a chain
    chain_heads = []
    for block in blocks:
        succs = block.get("succs", [])
        if len(succs) == 2 and block.get("compares_state"):
            chain_heads.append(block)

    if len(chain_heads) >= 3:
        # Find the first block in the chain (entry point of dispatcher)
        dispatcher = chain_heads[0]
        case_blocks = []
        for block in blocks:
            if block["addr"] == dispatcher["addr"]:
                continue
            if dispatcher["addr"] in block.get("succs", []) and "state_update" in block:
                case_blocks.append(block["addr"])

        if len(case_blocks) >= 2:
            return {
                "type": "tigress_ifchain",
                "dispatcher": dispatcher["addr"],
                "case_blocks": case_blocks,
                "chain_blocks": [b["addr"] for b in chain_heads],
                "num_cases": len(case_blocks),
            }

    return None


def deflat_tigress(params: dict[str, Any]) -> dict[str, Any]:
    """Main entry for Tigress deflattening."""
    blocks = params["blocks"]
    binary_bytes = bytes.fromhex(params["binary_hex"])
    arch = params.get("arch", "x86_64")

    # Try Tigress-specific detection first
    pattern = detect_tigress_pattern(blocks)

    if pattern is None:
        # Fall back to generic detection
        generic = detect_cff_pattern(blocks)
        if generic is None:
            return {"status": "no_cff_detected", "patches": []}
        pattern = generic

    # For Tigress indirect jumps, we need to read the jump table
    if pattern["type"] == "tigress_indirect" and "jump_table" in pattern:
        return {
            "status": "deobfuscated",
            "pattern": pattern,
            "transitions": _resolve_jump_table(pattern["jump_table"], blocks),
            "patches": [],  # patch generation TBD
        }

    # For if-chain, similar to OLLVM but need to handle the chain structure
    return {
        "status": "deobfuscated",
        "pattern": pattern,
        "transitions": [],
        "patches": [],
    }


def _resolve_jump_table(
    jump_table: list[int],
    blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve jump table entries to block addresses."""
    block_addrs = {b["addr"] for b in blocks}
    transitions = []
    for i, target in enumerate(jump_table):
        if target in block_addrs:
            transitions.append({
                "table_index": i,
                "target": target,
            })
    return transitions
