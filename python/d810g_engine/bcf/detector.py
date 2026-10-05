"""Detect and remove OLLVM Bogus Control Flow patterns."""

from __future__ import annotations
from typing import Any

from d810g_engine.opaque.predicate import classify_predicate


def detect_bcf_candidates(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find blocks that look like BCF-inserted conditional branches.

    BCF signature:
    - A block with exactly 2 successors (conditional branch)
    - One successor leads to the "real" continuation
    - The other successor leads to a "bogus" block
    - The bogus block often contains junk code or is structurally similar to the real block
    - The condition guarding the branch is an opaque predicate
    """
    candidates = []
    block_map = {b["addr"]: b for b in blocks}

    for block in blocks:
        succs = block.get("succs", [])
        if len(succs) != 2:
            continue

        condition = block.get("condition")
        if not condition:
            continue

        true_target, false_target = succs[0], succs[1]
        true_block = block_map.get(true_target)
        false_block = block_map.get(false_target)

        if not true_block or not false_block:
            continue

        # Check if both successors converge to the same block (BCF hallmark)
        true_succs = set(true_block.get("succs", []))
        false_succs = set(false_block.get("succs", []))
        convergence = true_succs & false_succs

        if not convergence:
            continue

        # Check if the condition is an opaque predicate
        result = classify_predicate(
            condition,
            bit_width=block.get("bit_width", 32),
            signed=block.get("signed", True),
            timeout_ms=2000,
        )

        if result["classification"] in ("always_true", "always_false"):
            # Determine which branch is real and which is bogus
            if result["classification"] == "always_true":
                real_target = true_target
                bogus_target = false_target
            else:
                real_target = false_target
                bogus_target = true_target

            candidates.append({
                "branch_addr": block["addr"],
                "condition": condition,
                "classification": result["classification"],
                "real_target": real_target,
                "bogus_target": bogus_target,
                "convergence_point": list(convergence)[0] if convergence else None,
            })

    return candidates


def generate_bcf_patches(
    candidates: list[dict[str, Any]],
    arch: str = "x86_64",
) -> list[dict[str, Any]]:
    """Generate patches to remove BCF by replacing conditional jumps with unconditional ones.

    For each BCF candidate:
    - Replace the conditional branch with an unconditional jump to the real target
    - NOP out the bogus block (optional, for cleanliness)
    """
    patches = []

    for candidate in candidates:
        patches.append({
            "address": candidate["branch_addr"],
            "action": "force_unconditional",
            "target": candidate["real_target"],
            "removed_bogus": candidate["bogus_target"],
            "original_condition": candidate["condition"],
        })

    return patches


def detect_and_remove_bcf(params: dict[str, Any]) -> dict[str, Any]:
    """Main entry point: detect BCF patterns and generate removal patches."""
    blocks = params["blocks"]
    arch = params.get("arch", "x86_64")

    candidates = detect_bcf_candidates(blocks)

    if not candidates:
        return {
            "status": "no_bcf_detected",
            "candidates": [],
            "patches": [],
        }

    patches = generate_bcf_patches(candidates, arch)

    return {
        "status": "bcf_removed",
        "candidates": [
            {
                "branch_addr": c["branch_addr"],
                "condition": c["condition"],
                "classification": c["classification"],
                "real_target": c["real_target"],
                "bogus_target": c["bogus_target"],
            }
            for c in candidates
        ],
        "patches": patches,
        "summary": f"Detected {len(candidates)} BCF patterns, generated {len(patches)} patches",
    }
