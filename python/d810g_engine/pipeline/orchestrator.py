"""Full deobfuscation pipeline — chains all passes in optimal order."""

from __future__ import annotations
import time
from typing import Any


class PipelinePass:
    """Represents a single analysis pass in the pipeline."""

    def __init__(self, name: str, handler, description: str = ""):
        self.name = name
        self.handler = handler
        self.description = description

    def run(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.handler(params)


class PipelineResult:
    """Accumulated results from the full pipeline."""

    def __init__(self):
        self.passes: list[dict[str, Any]] = []
        self.total_patches: int = 0
        self.total_time_ms: float = 0
        self.iterations: int = 0

    def add_pass_result(self, name: str, result: dict[str, Any], time_ms: float):
        patches = len(result.get("patches", []))
        self.passes.append({
            "name": name,
            "status": result.get("status", "ok"),
            "patches": patches,
            "time_ms": round(time_ms, 1),
            "details": _summarize(result),
        })
        self.total_patches += patches
        self.total_time_ms += time_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "iterations": self.iterations,
            "total_passes": len(self.passes),
            "total_patches": self.total_patches,
            "total_time_ms": round(self.total_time_ms, 1),
            "passes": self.passes,
        }


def _summarize(result: dict[str, Any]) -> str:
    """Extract a one-line summary from a pass result."""
    if "summary" in result:
        return result["summary"]
    status = result.get("status", "")
    patches = len(result.get("patches", []))
    if patches > 0:
        return f"{status}: {patches} patches"
    return status


def build_pipeline() -> list[PipelinePass]:
    """Build the standard deobfuscation pipeline in optimal pass order."""
    from d810g_engine.deflattener.ollvm import deflat_ollvm
    from d810g_engine.deflattener.tigress import deflat_tigress
    from d810g_engine.bcf.detector import detect_and_remove_bcf
    from d810g_engine.opaque import eliminate_predicates
    from d810g_engine.dce.eliminator import eliminate_dead_code
    from d810g_engine.strings.decryptor import decrypt_strings

    return [
        PipelinePass("deflat_ollvm", deflat_ollvm,
                     "OLLVM control flow deflattening"),
        PipelinePass("deflat_tigress", deflat_tigress,
                     "Tigress control flow deflattening"),
        PipelinePass("bcf", detect_and_remove_bcf,
                     "Bogus control flow removal"),
        PipelinePass("opaque", _wrap_opaque(eliminate_predicates),
                     "Opaque predicate elimination"),
        PipelinePass("dce", eliminate_dead_code,
                     "Dead code elimination"),
        PipelinePass("strings", decrypt_strings,
                     "String decryption"),
    ]


def _wrap_opaque(handler):
    """Wrap opaque predicate handler to accept standard block params."""
    def wrapped(params):
        predicates = params.get("predicates", [])
        if not predicates:
            # Extract conditions from blocks if not explicitly provided
            blocks = params.get("blocks", [])
            predicates = [
                {"expression": b["condition"], "address": b["addr"],
                 "bit_width": b.get("bit_width", 32)}
                for b in blocks if "condition" in b
            ]
        if not predicates:
            return {"status": "no_predicates", "patches": [], "results": []}
        return handler({"predicates": predicates})
    return wrapped


def run_pipeline(params: dict[str, Any]) -> dict[str, Any]:
    """Run the full deobfuscation pipeline.

    Params:
        blocks: basic block graph
        binary_hex: hex-encoded function bytes
        arch: architecture string
        entry_addr: function entry address
        sections: optional section info for string decryption
        max_iterations: max pipeline iterations (default 3)
        passes: optional list of pass names to run (default: all)
        verbose: include per-pass details (default True)
    """
    max_iterations = params.get("max_iterations", 3)
    enabled_passes = params.get("passes")
    verbose = params.get("verbose", True)

    all_passes = build_pipeline()

    # Filter passes if specific ones requested
    if enabled_passes:
        enabled_set = set(enabled_passes)
        all_passes = [p for p in all_passes if p.name in enabled_set]

    result = PipelineResult()

    # Mutable copy of params that evolves between passes
    current_params = dict(params)
    current_blocks = [dict(b) for b in params.get("blocks", [])]
    current_params["blocks"] = current_blocks

    # Track patches to avoid duplicates across iterations
    seen_patches: set[tuple] = set()

    for iteration in range(max_iterations):
        result.iterations = iteration + 1
        changes_this_round = 0

        for pipeline_pass in all_passes:
            start = time.time()

            try:
                pass_result = pipeline_pass.run(current_params)
            except Exception as e:
                pass_result = {
                    "status": f"error: {e}",
                    "patches": [],
                }

            elapsed = (time.time() - start) * 1000

            # Deduplicate patches
            new_patches = []
            for p in pass_result.get("patches", []):
                patch_key = (p.get("address", 0), p.get("action", ""), p.get("target", 0))
                if patch_key not in seen_patches:
                    seen_patches.add(patch_key)
                    new_patches.append(p)

            pass_result["patches"] = new_patches
            changes_this_round += len(new_patches)

            if verbose or len(new_patches) > 0:
                result.add_pass_result(pipeline_pass.name, pass_result, elapsed)

            # Update block graph based on pass results
            _apply_pass_effects(current_blocks, pipeline_pass.name, pass_result)
            current_params["blocks"] = current_blocks

        # If no changes this round, we've reached fixpoint
        if changes_this_round == 0:
            break

    output = result.to_dict()
    output["status"] = "completed"
    output["fixpoint"] = result.iterations < max_iterations or changes_this_round == 0
    output["summary"] = (
        f"Pipeline completed in {result.iterations} iteration(s): "
        f"{result.total_patches} total patches, "
        f"{result.total_time_ms:.0f}ms"
    )

    return output


def _apply_pass_effects(blocks: list[dict], pass_name: str, result: dict):
    """Update the block graph in-place based on a pass's results.

    After a pass produces patches, the block graph must reflect those changes
    so subsequent passes (and subsequent iterations) see the updated state
    instead of re-discovering the same issues.
    """
    if pass_name == "bcf":
        # BCF removed bogus branches -- update successors to only the real target
        for candidate in result.get("candidates", []):
            branch_addr = candidate.get("branch_addr")
            real_target = candidate.get("real_target")
            if branch_addr is None or real_target is None:
                continue
            for block in blocks:
                if block.get("addr") == branch_addr:
                    block["succs"] = [real_target]
                    block.pop("condition", None)
                    break

    elif pass_name == "opaque":
        # Opaque predicates eliminated -- remove resolved conditions
        for r in result.get("results", []):
            if r.get("classification") in ("always_true", "always_false"):
                addr = r.get("address")
                if addr is None:
                    continue
                for block in blocks:
                    if block.get("addr") == addr:
                        block.pop("condition", None)
                        break

    elif pass_name == "dce":
        # Dead blocks removed -- filter them out of the graph
        dead_addrs = {b["addr"] for b in result.get("dead_blocks", [])}
        if dead_addrs:
            blocks[:] = [b for b in blocks if b["addr"] not in dead_addrs]
            # Also remove dead addresses from successor lists
            for block in blocks:
                block["succs"] = [s for s in block.get("succs", [])
                                  if s not in dead_addrs]
