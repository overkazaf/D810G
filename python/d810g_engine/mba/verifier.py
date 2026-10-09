"""Z3-based equivalence verification for MBA rules."""

from __future__ import annotations
from typing import Any

from z3 import Solver, Not, sat, unsat, is_app, is_bool

from d810g_engine.parser import eval_z3

# Operators whose operands may be swapped when matching congruent terms.
_COMMUTATIVE = frozenset({"bvadd", "bvmul", "bvand", "bvor", "bvxor", "=", "distinct"})


def verify_equivalence(pattern: str, replacement: str, bit_width: int = 32) -> bool:
    """Verify that pattern and replacement are equivalent for all inputs using Z3.

    Returns False (fail-safe) if an expression contains unsupported constructs
    such as function calls (abs, min, max, sign) so that broken rules are
    never silently accepted, or if Z3 cannot decide within the time limit.
    """
    return prove_equivalence(pattern, replacement, bit_width=bit_width)["result"] == "equivalent"


def prove_equivalence(
    lhs_str: str,
    rhs_str: str,
    bit_width: int = 32,
    signed: bool = True,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    """Prove ``lhs == rhs`` for all inputs, or produce a counterexample.

    Returns ``{"result": "equivalent" | "counterexample" | "unknown" | "error", ...}``.
    A counterexample carries ``inputs`` (variable -> value) plus the value each
    side evaluates to.  Unassigned variables are reported as 0.
    """
    try:
        # Z3 matches variables by name, so separately parsed sides share symbols.
        lhs, vars_lhs = eval_z3(lhs_str, bit_width=bit_width, signed=signed)
        rhs, vars_rhs = eval_z3(rhs_str, bit_width=bit_width, signed=signed)
    except ValueError as e:
        return {"result": "error", "error": f"parse error: {e}"}

    if is_bool(lhs) != is_bool(rhs):
        return {"result": "error",
                "error": "one side is a predicate, the other is a value"}

    status, model = _prove(lhs, rhs, timeout_ms)
    if status != "counterexample":
        return {"result": status}

    inputs = {}
    for name, var in sorted({**vars_lhs, **vars_rhs}.items()):
        inputs[name] = model.eval(var, model_completion=True).as_long()
    return {
        "result": "counterexample",
        "counterexample": {
            "inputs": inputs,
            "original_value": _model_value(model, lhs),
            "candidate_value": _model_value(model, rhs),
        },
    }


def _model_value(model, expr):
    val = model.eval(expr, model_completion=True)
    return bool(val) if is_bool(val) else val.as_long()


def _prove(lhs, rhs, timeout_ms: int, depth: int = 4):
    """Return ``(status, model)``.

    Nonlinear terms (``(a|C) * (b^C)`` against its IS-obfuscated twin) can stall
    the bit-blaster indefinitely, so congruent terms are first split by
    operator: ``f(a1, a2) == f(b1, b2)`` holds when each ``ai == bi`` holds.
    That is sufficient but not necessary, so a full query follows on failure.
    *depth* bounds the split so failed attempts cannot blow up exponentially.
    """
    if (depth > 0 and is_app(lhs) and is_app(rhs) and lhs.num_args() > 0
            and lhs.decl().name() == rhs.decl().name()
            and lhs.num_args() == rhs.num_args()
            and lhs.decl().params() == rhs.decl().params()):
        l_args, r_args = lhs.children(), rhs.children()
        orders = [r_args]
        if lhs.decl().name() in _COMMUTATIVE and len(r_args) == 2:
            orders.append(r_args[::-1])
        for args in orders:
            if all(_prove(a, b, timeout_ms, depth - 1)[0] == "equivalent"
                   for a, b in zip(l_args, args)):
                return "equivalent", None

    solver = Solver()
    solver.set("timeout", timeout_ms)
    solver.add(Not(lhs == rhs))
    res = solver.check()
    if res == unsat:
        return "equivalent", None
    if res == sat:
        return "counterexample", solver.model()
    return "unknown", None
