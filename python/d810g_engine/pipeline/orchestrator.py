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

    for iteration in range(max_iterations):
        result.iterations = iteration + 1
        changes_this_round = 0

        for pipeline_pass in all_passes:
            start = time.time()

            try:
                pass_result = pipeline_pass.run(params)
            except Exception as e:
                pass_result = {
                    "status": f"error: {e}",
                    "patches": [],
                }

            elapsed = (time.time() - start) * 1000
            patches = len(pass_result.get("patches", []))
            changes_this_round += patches

            if verbose or patches > 0:
                result.add_pass_result(pipeline_pass.name, pass_result, elapsed)

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
