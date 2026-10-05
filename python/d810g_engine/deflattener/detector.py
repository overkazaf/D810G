"""Detect control flow flattening patterns in basic block graphs."""

from __future__ import annotations
from typing import Any


def detect_cff_pattern(blocks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Detect OLLVM-style switch dispatcher pattern.

    Looks for a block with 3+ successors where multiple blocks jump back to it
    with state variable updates — the classic CFF dispatcher signature.
    """
    for block in blocks:
        succs = block.get("succs", [])
        if len(succs) < 3:
            continue
        back_edges = 0
        case_blocks = []
        for other in blocks:
            if other["addr"] == block["addr"]:
                continue
            if block["addr"] in other.get("succs", []):
                back_edges += 1
                if "state_update" in other:
                    case_blocks.append(other["addr"])
        if back_edges >= 2 and len(case_blocks) >= 2:
            return {
                "type": "ollvm_switch",
                "dispatcher": block["addr"],
                "case_blocks": case_blocks,
                "num_cases": len(succs),
            }
    return None
