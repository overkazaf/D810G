"""Z3-based equivalence verification for MBA rules."""

from __future__ import annotations
from z3 import BitVec, BitVecVal, Solver, Not, unsat


def verify_equivalence(pattern: str, replacement: str, bit_width: int = 32) -> bool:
    """Verify that pattern and replacement are equivalent for all inputs using Z3."""
    variables: dict[str, any] = {}

    def _get_var(name: str):
        if name not in variables:
            variables[name] = BitVec(name, bit_width)
        return variables[name]

    def _eval(expr_str: str):
        expr_str = expr_str.strip()
        if expr_str.isidentifier():
            return _get_var(expr_str)
        if expr_str.isdigit():
            return BitVecVal(int(expr_str), bit_width)
        if expr_str.startswith("~"):
            inner = expr_str[1:].strip()
            if inner.startswith("("):
                inner = inner[1:-1]
            return ~_eval(inner)
        if expr_str.startswith("-") and len(expr_str) > 1 and not expr_str[1:].strip()[0].isdigit():
            return -_eval(expr_str[1:].strip())

        if expr_str.startswith("(") and expr_str.endswith(")"):
            depth = 0
            for i, c in enumerate(expr_str):
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                if depth == 0 and i < len(expr_str) - 1:
                    break
            else:
                expr_str = expr_str[1:-1].strip()

        ops = [
            ("|", lambda a, b: a | b),
            ("^", lambda a, b: a ^ b),
            ("+", lambda a, b: a + b),
            ("-", lambda a, b: a - b),
            ("&", lambda a, b: a & b),
            ("*", lambda a, b: a * b),
        ]
        for op_char, op_fn in ops:
            depth = 0
            for i in range(len(expr_str) - 1, -1, -1):
                if expr_str[i] == ")":
                    depth += 1
                elif expr_str[i] == "(":
                    depth -= 1
                elif depth == 0 and expr_str[i] == op_char:
                    if op_char == "-" and i == 0:
                        continue
                    left = expr_str[:i].strip()
                    right = expr_str[i + 1:].strip()
                    if left and right:
                        return op_fn(_eval(left), _eval(right))
        return _get_var(expr_str)

    lhs = _eval(pattern)
    rhs = _eval(replacement)

    solver = Solver()
    solver.add(Not(lhs == rhs))
    return solver.check() == unsat
