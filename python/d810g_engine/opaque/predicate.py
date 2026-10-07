"""Opaque predicate detection and classification using Z3."""

from __future__ import annotations
from typing import Any
from z3 import BitVec, BitVecVal, Solver, sat, unsat, Not, UGE, UGT, ULE, ULT, URem, SRem, is_bool


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

    variables: dict[str, Any] = {}

    def _get_var(name: str):
        if name not in variables:
            variables[name] = BitVec(name, bit_width)
        return variables[name]

    def _eval(s: str):
        s = s.strip()
        if not s:
            raise ValueError("empty subexpression")
        if s.isidentifier():
            return _get_var(s)
        if s.startswith("0x") or s.startswith("0X"):
            return BitVecVal(int(s, 16), bit_width)
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return BitVecVal(int(s), bit_width)

        if s.startswith("(") and s.endswith(")"):
            depth = 0
            for i, c in enumerate(s):
                if c == "(": depth += 1
                elif c == ")": depth -= 1
                if depth == 0 and i < len(s) - 1:
                    break
            else:
                s = s[1:-1].strip()

        # Comparison operators (lowest precedence in conditions)
        for cmp_op, cmp_fn in [
            ("!=", lambda a, b: a != b),
            ("==", lambda a, b: a == b),
            (">=", lambda a, b: a >= b if signed else UGE(a, b)),
            ("<=", lambda a, b: a <= b if signed else ULE(a, b)),
            (">", lambda a, b: a > b if signed else UGT(a, b)),
            ("<", lambda a, b: a < b if signed else ULT(a, b)),
        ]:
            depth = 0
            for i in range(len(s) - len(cmp_op), -1, -1):
                if s[i] == ")": depth += 1
                elif s[i] == "(": depth -= 1
                elif depth == 0 and s[i:i + len(cmp_op)] == cmp_op:
                    left = s[:i].strip()
                    right = s[i + len(cmp_op):].strip()
                    if left and right:
                        return cmp_fn(_eval(left), _eval(right))

        # Arithmetic/bitwise operators
        for op_char, op_fn in [
            ("|", lambda a, b: a | b),
            ("^", lambda a, b: a ^ b),
            ("+", lambda a, b: a + b),
            ("-", lambda a, b: a - b),
            ("&", lambda a, b: a & b),
            ("%", lambda a, b: URem(a, b) if not signed else SRem(a, b)),
            ("*", lambda a, b: a * b),
        ]:
            depth = 0
            for i in range(len(s) - 1, -1, -1):
                if s[i] == ")": depth += 1
                elif s[i] == "(": depth -= 1
                elif depth == 0 and s[i] == op_char:
                    if op_char == "-" and i == 0:
                        continue
                    left = s[:i].strip()
                    right = s[i + 1:].strip()
                    if left and right:
                        return op_fn(_eval(left), _eval(right))

        return _get_var(s)

    try:
        predicate = _eval(expr_str)
    except Exception as e:
        return {
            "expression": expr_str,
            "classification": "error",
            "error": f"parse error: {e}",
            "variables": list(variables.keys()),
        }

    # If _eval returns a non-boolean Z3 expression (e.g., pure arithmetic),
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
