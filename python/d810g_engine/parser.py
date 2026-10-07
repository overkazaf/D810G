"""Shared expression parser for D810G -- used by MBA, opaque, and verifier modules.

Consolidates the four duplicate parsers (mba/matcher.py, mba/verifier.py,
opaque/predicate.py, opaque/advanced.py) into one tokenizer + one
recursive-descent parser with pluggable output modes.

Operator precedence (lowest to highest):
    comparison (== != < <= > >=)
    |
    ^
    + -
    &
    << >>
    * / %
    unary (- ~)
"""

from __future__ import annotations

import re as _re
from typing import Any


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TWO_CHAR_OPS = frozenset({"==", "!=", "<=", ">=", "<<", ">>"})
_SINGLE_OPS = frozenset("+-*/%&|^~()")
_COMPARE_OPS = frozenset({"==", "!=", "<", "<=", ">", ">="})


def _tokenize(expr: str) -> list[str]:
    """Tokenize an expression string into a list of tokens.

    Supports: decimal integers, hex integers (0x...), identifiers,
    single-char operators, and two-char operators (<<, >>, ==, !=, <=, >=).
    """
    tokens: list[str] = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]

        # skip whitespace
        if c.isspace():
            i += 1
            continue

        # two-character operators (check before single-char)
        if i + 1 < n:
            two = expr[i : i + 2]
            if two in _TWO_CHAR_OPS:
                tokens.append(two)
                i += 2
                continue

        # single-character operators
        if c in _SINGLE_OPS:
            tokens.append(c)
            i += 1
            continue

        # bare < or > (not part of a two-char token)
        if c in "<>":
            tokens.append(c)
            i += 1
            continue

        # hex literal  0x... / 0X...
        if c == "0" and i + 1 < n and expr[i + 1] in "xX":
            j = i + 2
            while j < n and expr[j] in "0123456789abcdefABCDEF":
                j += 1
            if j == i + 2:
                raise ValueError(f"Invalid hex literal at position {i}")
            tokens.append(expr[i:j])
            i = j
            continue

        # decimal integer
        if c.isdigit():
            j = i
            while j < n and expr[j].isdigit():
                j += 1
            tokens.append(expr[i:j])
            i = j
            continue

        # identifier
        if c.isalpha() or c == "_":
            j = i
            while j < n and (expr[j].isalnum() or expr[j] == "_"):
                j += 1
            tokens.append(expr[i:j])
            i = j
            continue

        raise ValueError(f"Unsupported character: '{c}' at position {i}")

    return tokens


# ---------------------------------------------------------------------------
# Public API -- Z3 mode
# ---------------------------------------------------------------------------


def eval_z3(
    expr_str: str,
    bit_width: int = 32,
    signed: bool = True,
    use_integers: bool = False,
):
    """Parse *expr_str* and return a Z3 expression.

    Args:
        expr_str: infix expression (e.g. ``"(x ^ y) + 1"``).
        bit_width: bitvector width; ignored when *use_integers* is True.
        signed: use signed comparisons / remainder in bitvector mode.
        use_integers: use ``z3.Int`` instead of ``z3.BitVec`` -- useful for
            number-theory proofs where bitvector overflow hides the identity.

    Returns:
        ``(z3_expr, variables_dict)`` where *variables_dict* maps each
        variable name that appeared in the expression to its Z3 symbol.

    Raises:
        ValueError: on function calls (``name(...)``), unsupported tokens,
            or operators not available in integer mode.
    """
    # Reject function calls early -- the parser cannot represent them.
    if _re.search(r"[a-zA-Z_]\w*\s*\(", expr_str):
        raise ValueError("function calls are not supported")

    # -- choose constructor helpers based on mode --------------------------
    if use_integers:
        from z3 import Int, IntVal

        _make_var = Int
        _make_const = IntVal
    else:
        from z3 import BitVec, BitVecVal

        def _make_var(name: str):
            return BitVec(name, bit_width)

        def _make_const(val: int):
            return BitVecVal(val, bit_width)

    variables: dict[str, Any] = {}

    def _get_var(name: str):
        if name not in variables:
            variables[name] = _make_var(name)
        return variables[name]

    # -- operator helpers --------------------------------------------------

    def _apply_mod(left, right):
        if use_integers:
            return left % right
        from z3 import URem, SRem

        return SRem(left, right) if signed else URem(left, right)

    def _apply_div(left, right):
        if use_integers:
            return left / right
        if not signed:
            from z3 import UDiv

            return UDiv(left, right)
        return left / right

    def _apply_shr(left, right):
        if use_integers:
            raise ValueError("shift operators not supported in integer mode")
        from z3 import LShR

        return LShR(left, right)

    def _apply_shl(left, right):
        if use_integers:
            raise ValueError("shift operators not supported in integer mode")
        return left << right

    def _apply_bitwise(op_char, left, right):
        if use_integers:
            raise ValueError(
                f"bitwise operator '{op_char}' not supported in integer mode"
            )
        if op_char == "&":
            return left & right
        if op_char == "|":
            return left | right
        if op_char == "^":
            return left ^ right
        raise ValueError(f"unknown bitwise op: {op_char}")  # pragma: no cover

    def _apply_bitnot(operand):
        if use_integers:
            raise ValueError("bitwise NOT (~) not supported in integer mode")
        return ~operand

    def _apply_cmp(op: str, left, right):
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if not use_integers and not signed:
            from z3 import UGE, UGT, ULE, ULT

            return {
                "<": ULT,
                "<=": ULE,
                ">": UGT,
                ">=": UGE,
            }[op](left, right)
        # signed bitvector or integer mode -- plain Python comparison
        return {
            "<": lambda a, b: a < b,
            "<=": lambda a, b: a <= b,
            ">": lambda a, b: a > b,
            ">=": lambda a, b: a >= b,
        }[op](left, right)

    # -- recursive-descent parser ------------------------------------------

    tokens = _tokenize(expr_str)
    pos = [0]  # mutable counter shared by closures

    def _cur():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def _advance():
        pos[0] += 1

    def _parse_comparison():
        left = _parse_or()
        if _cur() in _COMPARE_OPS:
            op = _cur()
            _advance()
            right = _parse_or()
            return _apply_cmp(op, left, right)
        return left

    def _parse_or():
        left = _parse_xor()
        while _cur() == "|":
            _advance()
            right = _parse_xor()
            left = _apply_bitwise("|", left, right)
        return left

    def _parse_xor():
        left = _parse_add_sub()
        while _cur() == "^":
            _advance()
            right = _parse_add_sub()
            left = _apply_bitwise("^", left, right)
        return left

    def _parse_add_sub():
        left = _parse_and()
        while _cur() in ("+", "-"):
            op = _cur()
            _advance()
            right = _parse_and()
            left = (left + right) if op == "+" else (left - right)
        return left

    def _parse_and():
        left = _parse_shift()
        while _cur() == "&":
            _advance()
            right = _parse_shift()
            left = _apply_bitwise("&", left, right)
        return left

    def _parse_shift():
        left = _parse_mul_div_mod()
        while _cur() in ("<<", ">>"):
            op = _cur()
            _advance()
            right = _parse_mul_div_mod()
            left = _apply_shl(left, right) if op == "<<" else _apply_shr(left, right)
        return left

    def _parse_mul_div_mod():
        left = _parse_unary()
        while _cur() in ("*", "/", "%"):
            op = _cur()
            _advance()
            right = _parse_unary()
            if op == "*":
                left = left * right
            elif op == "/":
                left = _apply_div(left, right)
            else:
                left = _apply_mod(left, right)
        return left

    def _parse_unary():
        if _cur() == "~":
            _advance()
            operand = _parse_unary()
            return _apply_bitnot(operand)
        if _cur() == "-":
            _advance()
            operand = _parse_unary()
            return -operand
        return _parse_atom()

    def _parse_atom():
        tok = _cur()
        if tok is None:
            raise ValueError("Unexpected end of expression")

        if tok == "(":
            _advance()
            result = _parse_comparison()
            if _cur() == ")":
                _advance()
            else:
                raise ValueError("Missing closing parenthesis")
            return result

        # hex literal
        if len(tok) > 2 and tok[:2] in ("0x", "0X"):
            _advance()
            return _make_const(int(tok, 16))

        # decimal literal
        if tok[0].isdigit():
            _advance()
            return _make_const(int(tok))

        # identifier (variable)
        if tok[0].isalpha() or tok[0] == "_":
            _advance()
            # function-call guard (belt + suspenders -- regex already checked)
            if _cur() == "(":
                raise ValueError(f"Function calls not supported: {tok}(...)")
            return _get_var(tok)

        raise ValueError(f"Unexpected token: {tok!r}")

    # -- execute -----------------------------------------------------------

    result = _parse_comparison()
    if pos[0] < len(tokens):
        raise ValueError(f"Unexpected trailing tokens: {tokens[pos[0]:]}")

    return result, variables
