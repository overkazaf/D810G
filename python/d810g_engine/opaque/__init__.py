"""Opaque predicate elimination module."""

from __future__ import annotations
from typing import Any

from d810g_engine.opaque.predicate import classify_predicate


def eliminate_predicates(params: dict[str, Any]) -> dict[str, Any]:
    """Classify and eliminate opaque predicates, returning patches."""
    results = []
    for pred in params.get("predicates", []):
        result = classify_predicate(
            pred["expression"],
            bit_width=pred.get("bit_width", 32),
            signed=pred.get("signed", True),
        )
        result["address"] = pred.get("address")
        results.append(result)

    patches = []
    for r in results:
        if r["classification"] == "always_true":
            patches.append({"address": r["address"], "action": "force_true"})
        elif r["classification"] == "always_false":
            patches.append({"address": r["address"], "action": "force_false"})

    return {"results": results, "patches": patches}


def register_handlers(server: Any) -> None:
    """Register opaque predicate handlers on the server."""
    server.register("opaque.classify", lambda p: classify_predicate(**p))
    server.register("opaque.eliminate", eliminate_predicates)

    from d810g_engine.opaque.advanced import classify_advanced, batch_classify_advanced
    server.register("opaque.classify_advanced", lambda p: classify_advanced(**p))
    server.register("opaque.batch_advanced", batch_classify_advanced)
