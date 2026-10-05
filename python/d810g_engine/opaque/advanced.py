"""Advanced opaque predicate detection -- number theory and multi-variable predicates."""

from __future__ import annotations
from typing import Any

from z3 import (
    BitVec, BitVecVal, Solver, sat, unsat, Not, And, Or, ForAll,
    Int, IntVal, ArithRef, Exists,
)


# Classic number theory opaque predicates
# These are mathematically proven properties that are always true
KNOWN_PATTERNS = [
    {
        "id": "nt_square_mod4",
        "description": "x^2 mod 4 is always 0 or 1",
        "predicate": lambda x: Or(x * x % 4 == 0, x * x % 4 == 1),
        "classification": "always_true",
    },
    {
        "id": "nt_even_product",
        "description": "x*(x+1) is always even",
        "predicate": lambda x: (x * (x + 1)) % 2 == 0,
        "classification": "always_true",
    },
    {
        "id": "nt_sum_consecutive",
        "description": "x + (x+1) + (x+2) is always divisible by 3",
        "predicate": lambda x: (x + (x + 1) + (x + 2)) % 3 == 0,
        "classification": "always_true",
    },
    {
        "id": "nt_diff_squares",
        "description": "x^2 - y^2 = (x+y)(x-y) factorization check",
        "predicate": lambda x, y: x * x - y * y == (x + y) * (x - y),
        "classification": "always_true",
    },
]


def classify_advanced(
    expr_str: str,
    bit_width: int = 32,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    """Extended opaque predicate classification.

    1. First try standard Z3 bitvector analysis
    2. If inconclusive, try integer arithmetic mode (unbounded)
    3. Check against known number theory patterns
    """
    from d810g_engine.opaque.predicate import classify_predicate

    # Step 1: Standard bitvector analysis
    result = classify_predicate(expr_str, bit_width=bit_width, timeout_ms=timeout_ms)

    if result["classification"] != "dynamic":
        result["method"] = "bitvector"
        return result

    # Step 2: Try with integer arithmetic (avoids bitvector overflow issues)
    int_result = _classify_with_integers(expr_str, timeout_ms)
    if int_result and int_result != "dynamic":
        return {
            "expression": expr_str,
            "classification": int_result,
            "method": "integer_arithmetic",
            "variables": result.get("variables", []),
            "note": "Proven via integer arithmetic (may differ from bitvector semantics)",
        }

    # Step 3: Pattern matching against known number theory predicates
    pattern_match = _match_known_pattern(expr_str)
    if pattern_match:
        return {
            "expression": expr_str,
            "classification": pattern_match["classification"],
            "method": "pattern_match",
            "pattern_id": pattern_match["id"],
            "pattern_description": pattern_match["description"],
            "variables": result.get("variables", []),
        }

    # No luck -- it's genuinely dynamic (or too complex)
    result["method"] = "bitvector"
    return result


def _classify_with_integers(expr_str: str, timeout_ms: int = 10000) -> str | None:
    """Try classification using Z3 integer arithmetic instead of bitvectors."""
    variables: dict[str, Any] = {}

    def _get_var(name: str):
        if name not in variables:
            variables[name] = Int(name)
        return variables[name]

    def _eval(s: str):
        s = s.strip()
        if s.isidentifier():
            return _get_var(s)
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return IntVal(int(s))

        if s.startswith("(") and s.endswith(")"):
            depth = 0
            for i, c in enumerate(s):
                if c == "(": depth += 1
                elif c == ")": depth -= 1
                if depth == 0 and i < len(s) - 1:
                    break
            else:
                s = s[1:-1].strip()

        for cmp_op, cmp_fn in [
            ("!=", lambda a, b: a != b),
            ("==", lambda a, b: a == b),
            (">=", lambda a, b: a >= b),
            ("<=", lambda a, b: a <= b),
            (">", lambda a, b: a > b),
            ("<", lambda a, b: a < b),
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

        for op_char, op_fn in [
            ("+", lambda a, b: a + b),
            ("-", lambda a, b: a - b),
            ("*", lambda a, b: a * b),
            ("%", lambda a, b: a % b),
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
    except Exception:
        return None

    solver = Solver()
    solver.set("timeout", timeout_ms)

    solver.push()
    solver.add(Not(predicate))
    can_be_false = solver.check()
    solver.pop()

    solver.push()
    solver.add(predicate)
    can_be_true = solver.check()
    solver.pop()

    if can_be_false == unsat and can_be_true == sat:
        return "always_true"
    elif can_be_true == unsat and can_be_false == sat:
        return "always_false"

    return "dynamic"


def _match_known_pattern(expr_str: str) -> dict[str, Any] | None:
    """Match expression against known number theory opaque predicate patterns."""
    expr_lower = expr_str.lower().replace(" ", "")

    # Simple string-based pattern matching for common forms
    patterns = [
        {
            "id": "nt_xor_self",
            "match": lambda e: "^" in e and e.split("^")[0].strip() == e.split("^")[1].strip() if "^" in e and e.count("^") == 1 else False,
            "classification": "always_false",
            "description": "x ^ x is always 0",
        },
    ]

    for pattern in patterns:
        try:
            if pattern["match"](expr_str):
                return pattern
        except Exception:
            continue

    return None


def batch_classify_advanced(params: dict[str, Any]) -> dict[str, Any]:
    """Batch classify predicates using advanced analysis."""
    predicates = params.get("predicates", [])
    bit_width = params.get("bit_width", 32)
    timeout_ms = params.get("timeout_ms", 10000)

    results = []
    opaque_count = 0

    for pred in predicates:
        expr = pred.get("expression", pred) if isinstance(pred, dict) else pred
        bw = pred.get("bit_width", bit_width) if isinstance(pred, dict) else bit_width

        result = classify_advanced(expr, bit_width=bw, timeout_ms=timeout_ms)
        if isinstance(pred, dict) and "address" in pred:
            result["address"] = pred["address"]
        results.append(result)

        if result["classification"] in ("always_true", "always_false"):
            opaque_count += 1

    return {
        "results": results,
        "total": len(results),
        "opaque_count": opaque_count,
        "dynamic_count": len(results) - opaque_count,
    }
