"""Detect control flow flattening patterns in basic block graphs."""

from __future__ import annotations
from typing import Any


def state_machine_evidence(
    blocks: list[dict[str, Any]],
    case_addrs: list[int],
) -> dict[str, Any] | None:
    """Check that back-edge blocks drive a single state variable.

    A flattened dispatcher is re-entered with a *different* state per
    original successor, all written to the *same* variable.  A real loop
    (e.g. ``for (;;) switch (getc()) { case 'a': seen = 1; continue; }``)
    jumps back too, but its constant writes are identical or scattered over
    unrelated variables -- treating it as CFF would patch away a real loop.

    Returns ``{"state_values": [...], "state_var": str | None}`` or None.
    """
    by_addr = {b["addr"]: b for b in blocks}
    cases = [by_addr[a] for a in case_addrs if a in by_addr]

    values = {b["state_update"] for b in cases}
    if len(values) < 2:
        return None

    # state_var is optional -- only enforced when the block graph provides it.
    state_vars = {b["state_var"] for b in cases if "state_var" in b}
    if len(state_vars) > 1:
        return None

    return {
        "state_values": sorted(values),
        "state_var": state_vars.pop() if state_vars else None,
    }


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
            evidence = state_machine_evidence(blocks, case_blocks)
            if evidence is None:
                continue  # loop with constant writes, not a state machine
            return {
                "type": "ollvm_switch",
                "dispatcher": block["addr"],
                "case_blocks": case_blocks,
                "num_cases": len(succs),
                **evidence,
            }
    return None
