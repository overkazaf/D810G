"""Z3-based equivalence verification for MBA rules."""

from __future__ import annotations
import re as _re
from z3 import BitVec, BitVecVal, LShR, URem, Solver, Not, unsat


def verify_equivalence(pattern: str, replacement: str, bit_width: int = 32) -> bool:
    """Verify that pattern and replacement are equivalent for all inputs using Z3.

    Returns False (fail-safe) if an expression contains unsupported constructs
    such as function calls (abs, min, max, sign) so that broken rules are
    never silently accepted.
    """
    # Reject function calls -- the parser cannot represent them
    if _re.search(r'[a-zA-Z_]\w*\s*\(', pattern) or _re.search(r'[a-zA-Z_]\w*\s*\(', replacement):
        return False

    variables: dict[str, any] = {}

    def _get_var(name: str):
        if name not in variables:
            variables[name] = BitVec(name, bit_width)
        return variables[name]

    # ---------- tokenizer ----------

    _OP_CHARS = set("+-*&|^~()")
    _SHIFT_CHARS = set("<>")

    def _tokenize(expr: str) -> list[str]:
        tokens: list[str] = []
        i = 0
        while i < len(expr):
            c = expr[i]
            if c.isspace():
                i += 1
                continue
            if c in _OP_CHARS:
                tokens.append(c)
                i += 1
            elif c in _SHIFT_CHARS:
                # Handle << and >> as two-character tokens
                if i + 1 < len(expr) and expr[i + 1] == c:
                    tokens.append(c + c)
                    i += 2
                else:
                    raise ValueError(f"Unsupported character: lone '{c}' at position {i}")
            elif c == "/":
                tokens.append("/")
                i += 1
            elif c == "%":
                tokens.append("%")
                i += 1
            elif c.isdigit():
                j = i
                while j < len(expr) and expr[j].isdigit():
                    j += 1
                tokens.append(expr[i:j])
                i = j
            elif c.isalpha() or c == "_":
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] == "_"):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            else:
                raise ValueError(f"Unsupported character: '{c}' at position {i}")
        return tokens

    # ---------- recursive-descent parser ----------
    # Precedence (lowest to highest): | < ^ < +/- < & < shift < * / % < unary(~ -)

    tokens: list[str] = []
    pos = [0]  # mutable position counter

    def _cur():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def _advance():
        pos[0] += 1

    def _parse_or():
        left = _parse_xor()
        while _cur() == "|":
            _advance()
            right = _parse_xor()
            left = left | right
        return left

    def _parse_xor():
        left = _parse_add_sub()
        while _cur() == "^":
            _advance()
            right = _parse_add_sub()
            left = left ^ right
        return left

    def _parse_add_sub():
        left = _parse_and()
        while _cur() in ("+", "-"):
            op = _cur()
            _advance()
            right = _parse_and()
            if op == "+":
                left = left + right
            else:
                left = left - right
        return left

    def _parse_and():
        left = _parse_shift()
        while _cur() == "&":
            _advance()
            right = _parse_shift()
            left = left & right
        return left

    def _parse_shift():
        left = _parse_mul_div()
        while _cur() in ("<<", ">>"):
            op = _cur()
            _advance()
            right = _parse_mul_div()
            if op == "<<":
                left = left << right
            else:
                left = LShR(left, right)  # logical shift right for bitvectors
        return left

    def _parse_mul_div():
        left = _parse_unary()
        while _cur() in ("*", "/", "%"):
            op = _cur()
            _advance()
            right = _parse_unary()
            if op == "*":
                left = left * right
            elif op == "/":
                left = left / right  # Z3 UDiv for bitvectors
            else:
                left = URem(left, right)
        return left

    def _parse_unary():
        if _cur() == "~":
            _advance()
            operand = _parse_unary()
            return ~operand
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
            _advance()  # consume (
            result = _parse_or()
            if _cur() == ")":
                _advance()  # consume )
            return result
        if tok.isdigit():
            _advance()
            return BitVecVal(int(tok), bit_width)
        if tok[0].isalpha() or tok[0] == "_":
            _advance()
            return _get_var(tok)
        raise ValueError(f"Unexpected token: {tok!r}")

    def _eval(expr_str: str):
        nonlocal tokens
        tokens = _tokenize(expr_str)
        pos[0] = 0
        result = _parse_or()
        if pos[0] < len(tokens):
            raise ValueError(f"Unexpected trailing tokens: {tokens[pos[0]:]}")
        return result

    try:
        lhs = _eval(pattern)
        rhs = _eval(replacement)
    except ValueError:
        return False  # fail-safe: reject unparseable expressions

    solver = Solver()
    solver.add(Not(lhs == rhs))
    return solver.check() == unsat
