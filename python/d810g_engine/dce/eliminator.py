"""Detect and eliminate dead (unreachable) code blocks."""

from __future__ import annotations
from typing import Any


def find_reachable_blocks(
    blocks: list[dict[str, Any]],
    entry_addr: int,
) -> set[int]:
    """BFS from entry to find all reachable blocks."""
    block_map = {b["addr"]: b for b in blocks}
    visited = set()
    queue = [entry_addr]

    while queue:
        addr = queue.pop(0)
        if addr in visited:
            continue
        visited.add(addr)

        block = block_map.get(addr)
        if block is None:
            continue

        for succ in block.get("succs", []):
            if succ not in visited:
                queue.append(succ)

    return visited


def find_dead_blocks(
    blocks: list[dict[str, Any]],
    entry_addr: int,
) -> list[dict[str, Any]]:
    """Find blocks that are not reachable from the entry point."""
    reachable = find_reachable_blocks(blocks, entry_addr)
    dead = []

    for block in blocks:
        if block["addr"] not in reachable:
            dead.append({
                "addr": block["addr"],
                "size": block.get("size", 0),
                "reason": "unreachable",
            })

    return dead


def generate_nop_patches(
    dead_blocks: list[dict[str, Any]],
    arch: str = "x86_64",
) -> list[dict[str, Any]]:
    """Generate NOP patches for dead code blocks."""
    nop_byte = {
        "x86_64": "90",
        "x86": "90",
        "aarch64": "1f2003d5",  # NOP in ARM64
        "arm64": "1f2003d5",
        "arm": "0000a0e1",      # MOV R0, R0 in ARM32
    }.get(arch.lower(), "90")

    patches = []
    for block in dead_blocks:
        if block["size"] > 0:
            if arch.lower() in ("x86_64", "x86"):
                nop_fill = nop_byte * block["size"]
            else:
                # ARM instructions are 4 bytes
                nop_count = block["size"] // 4
                nop_fill = nop_byte * nop_count

            patches.append({
                "address": block["addr"],
                "bytes": nop_fill,
                "size": block["size"],
                "action": "nop_fill",
            })

    return patches


def compute_dce_stats(
    blocks: list[dict[str, Any]],
    dead_blocks: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute statistics about dead code elimination."""
    total_blocks = len(blocks)
    dead_count = len(dead_blocks)
    total_size = sum(b.get("size", 0) for b in blocks)
    dead_size = sum(b.get("size", 0) for b in dead_blocks)

    return {
        "total_blocks": total_blocks,
        "dead_blocks": dead_count,
        "live_blocks": total_blocks - dead_count,
        "total_bytes": total_size,
        "dead_bytes": dead_size,
        "reduction_pct": round(dead_count / total_blocks * 100, 1) if total_blocks > 0 else 0,
    }


def eliminate_dead_code(params: dict[str, Any]) -> dict[str, Any]:
    """Main entry: find and eliminate dead code blocks.

    Params:
        blocks: basic block graph with {addr, succs, size}
        entry_addr: function entry point
        arch: architecture string
        nop_fill: whether to generate NOP patches (default True)
    """
    blocks = params["blocks"]
    entry_addr = params.get("entry_addr", blocks[0]["addr"] if blocks else 0)
    arch = params.get("arch", "x86_64")
    nop_fill = params.get("nop_fill", True)

    dead_blocks = find_dead_blocks(blocks, entry_addr)

    if not dead_blocks:
        return {
            "status": "no_dead_code",
            "dead_blocks": [],
            "patches": [],
            "stats": compute_dce_stats(blocks, []),
        }

    patches = generate_nop_patches(dead_blocks, arch) if nop_fill else []
    stats = compute_dce_stats(blocks, dead_blocks)

    return {
        "status": "dead_code_eliminated",
        "dead_blocks": dead_blocks,
        "patches": patches,
        "stats": stats,
        "summary": (
            f"Found {stats['dead_blocks']}/{stats['total_blocks']} dead blocks "
            f"({stats['dead_bytes']} bytes, {stats['reduction_pct']}% of function)"
        ),
    }
