"""Opaque predicate detection and classification using Z3."""

from __future__ import annotations
from typing import Any
from z3 import Solver, sat, unsat, Not, is_bool

from d810g_engine.parser import eval_z3


def classify_predicate(
    expr_str: str,
    bit_width: int = 32,
    signed: bool = True,
    timeout_ms: int = 5000,
) -> dict[str, Any]:
    """Classify a conditional expression as always_true, always_false, or dynamic.

    Uses Z3 to check satisfiability of both the predicate and its negation:
    - If negation is unsat: always_true
    - If predicate is unsat: always_false
    - Otherwise: dynamic (depends on input)
    """
    # Input validation
    if not expr_str or not expr_str.strip():
        return {
            "expression": expr_str or "",
            "classification": "error",
            "error": "empty expression",
            "variables": [],
        }

    try:
        predicate, variables = eval_z3(
            expr_str, bit_width=bit_width, signed=signed
        )
    except Exception as e:
        return {
            "expression": expr_str,
            "classification": "error",
            "error": f"parse error: {e}",
            "variables": [],
        }

    # If eval_z3 returns a non-boolean Z3 expression (e.g., pure arithmetic),
    # it can't be used as a predicate
    if not is_bool(predicate):
        return {
            "expression": expr_str,
            "classification": "error",
            "error": "expression is not a boolean predicate",
            "variables": list(variables.keys()),
        }

    try:
        solver = Solver()
        solver.set("timeout", timeout_ms)

        # Check if predicate can be false
        solver.push()
        solver.add(Not(predicate))
        can_be_false = solver.check()
        solver.pop()

        # Check if predicate can be true
        solver.push()
        solver.add(predicate)
        can_be_true = solver.check()
        solver.pop()
    except Exception as e:
        return {
            "expression": expr_str,
            "classification": "error",
            "error": f"solver error: {e}",
            "variables": list(variables.keys()),
        }

    if can_be_false == unsat and can_be_true == sat:
        classification = "always_true"
    elif can_be_true == unsat and can_be_false == sat:
        classification = "always_false"
    else:
        classification = "dynamic"

    return {
        "expression": expr_str,
        "classification": classification,
        "variables": list(variables.keys()),
    }
