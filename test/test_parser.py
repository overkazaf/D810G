"""Tests for the shared expression parser (d810g_engine.parser)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from z3 import BitVecVal, IntVal, is_bool, simplify

from d810g_engine.parser import eval_z3


# ---------------------------------------------------------------------------
# Basic arithmetic
# ---------------------------------------------------------------------------

class TestArithmetic:

    def test_addition(self):
        expr, vs = eval_z3("x + y")
        assert "x" in vs and "y" in vs

    def test_subtraction(self):
        expr, vs = eval_z3("x - y")
        assert "x" in vs and "y" in vs

    def test_multiplication(self):
        expr, vs = eval_z3("x * y")
        assert "x" in vs and "y" in vs

    def test_division(self):
        expr, vs = eval_z3("x / y")
        assert "x" in vs and "y" in vs

    def test_modulo(self):
        expr, vs = eval_z3("x % y")
        assert "x" in vs and "y" in vs

    def test_constant_folding(self):
        """3 + 4 with no variables."""
        expr, vs = eval_z3("3 + 4")
        assert len(vs) == 0
        assert simplify(expr).as_long() == 7


# ---------------------------------------------------------------------------
# Bitwise operators
# ---------------------------------------------------------------------------

class TestBitwise:

    def test_and(self):
        expr, vs = eval_z3("x & y")
        assert len(vs) == 2

    def test_or(self):
        expr, vs = eval_z3("x | y")
        assert len(vs) == 2

    def test_xor(self):
        expr, vs = eval_z3("x ^ y")
        assert len(vs) == 2

    def test_not(self):
        expr, vs = eval_z3("~x")
        assert len(vs) == 1

    def test_complex_bitwise(self):
        """(x | y) - (x & y) should parse without error."""
        expr, vs = eval_z3("(x | y) - (x & y)")
        assert "x" in vs and "y" in vs


# ---------------------------------------------------------------------------
# Shift operators
# ---------------------------------------------------------------------------

class TestShift:

    def test_left_shift(self):
        expr, vs = eval_z3("x << 2")
        assert "x" in vs

    def test_right_shift(self):
        expr, vs = eval_z3("x >> 3")
        assert "x" in vs

    def test_shift_with_expr(self):
        expr, vs = eval_z3("(x + 1) << y")
        assert "x" in vs and "y" in vs


# ---------------------------------------------------------------------------
# Comparison operators
# ---------------------------------------------------------------------------

class TestComparison:

    def test_equal(self):
        expr, vs = eval_z3("x == y")
        assert is_bool(expr)

    def test_not_equal(self):
        expr, vs = eval_z3("x != y")
        assert is_bool(expr)

    def test_less_than(self):
        expr, vs = eval_z3("x < y")
        assert is_bool(expr)

    def test_less_equal(self):
        expr, vs = eval_z3("x <= y")
        assert is_bool(expr)

    def test_greater_than(self):
        expr, vs = eval_z3("x > y")
        assert is_bool(expr)

    def test_greater_equal(self):
        expr, vs = eval_z3("x >= y")
        assert is_bool(expr)

    def test_comparison_with_arithmetic(self):
        """(x & 1) == 0 should be a boolean expression."""
        expr, vs = eval_z3("(x & 1) == 0")
        assert is_bool(expr)


# ---------------------------------------------------------------------------
# Hex literals
# ---------------------------------------------------------------------------

class TestHexLiterals:

    def test_hex_lowercase(self):
        expr, vs = eval_z3("x & 0xff")
        assert len(vs) == 1

    def test_hex_uppercase(self):
        expr, vs = eval_z3("x & 0XFF")
        assert len(vs) == 1

    def test_hex_value(self):
        """0x10 should equal 16."""
        expr, vs = eval_z3("0x10")
        assert simplify(expr).as_long() == 16

    def test_hex_comparison(self):
        expr, vs = eval_z3("(x & 0xff) == 0x41")
        assert is_bool(expr)


# ---------------------------------------------------------------------------
# Unary operators
# ---------------------------------------------------------------------------

class TestUnary:

    def test_negation(self):
        expr, vs = eval_z3("-x")
        assert "x" in vs

    def test_bitwise_not(self):
        expr, vs = eval_z3("~x")
        assert "x" in vs

    def test_double_negation(self):
        """--x should parse (double negation)."""
        expr, vs = eval_z3("--x")
        assert "x" in vs

    def test_neg_constant(self):
        expr, vs = eval_z3("-5")
        # -5 as a 32-bit bitvec is 2^32 - 5
        val = simplify(expr).as_long()
        assert val == (2**32 - 5)


# ---------------------------------------------------------------------------
# Operator precedence
# ---------------------------------------------------------------------------

class TestPrecedence:

    def test_mul_before_add(self):
        """x + y * z should be x + (y * z), not (x + y) * z."""
        from z3 import Solver, Not, BitVec, unsat
        expr1, _ = eval_z3("x + y * z")
        expr2, _ = eval_z3("x + (y * z)")
        s = Solver()
        s.add(Not(expr1 == expr2))
        assert s.check() == unsat

    def test_and_before_or(self):
        """Bitwise & should bind tighter than |."""
        from z3 import Solver, Not, unsat
        expr1, _ = eval_z3("x | y & z")
        # With our precedence: | < ^ < +/- < &, so & binds tighter
        # x | y & z  =  x | (y & z)   -- NO!
        # Actually our precedence is: | < ^ < +/- < & < << >> < * / %
        # So | is lower than &, meaning & binds tighter: x | (y & z)
        expr2, _ = eval_z3("x | (y & z)")
        s = Solver()
        s.add(Not(expr1 == expr2))
        assert s.check() == unsat

    def test_shift_before_and(self):
        """<< should bind tighter than &."""
        from z3 import Solver, Not, unsat
        expr1, _ = eval_z3("x & y << 2")
        expr2, _ = eval_z3("x & (y << 2)")
        s = Solver()
        s.add(Not(expr1 == expr2))
        assert s.check() == unsat


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestErrors:

    def test_function_call_rejected(self):
        with pytest.raises(ValueError, match="function call"):
            eval_z3("abs(x)")

    def test_function_call_with_spaces(self):
        with pytest.raises(ValueError, match="function call"):
            eval_z3("min (x, y)")

    def test_trailing_tokens(self):
        with pytest.raises(ValueError, match="trailing"):
            eval_z3("x + y z")

    def test_empty_expression(self):
        with pytest.raises(ValueError):
            eval_z3("")

    def test_invalid_hex(self):
        with pytest.raises(ValueError):
            eval_z3("0x")

    def test_unsupported_char(self):
        with pytest.raises(ValueError, match="Unsupported"):
            eval_z3("x @ y")


# ---------------------------------------------------------------------------
# Integer mode
# ---------------------------------------------------------------------------

class TestIntegerMode:

    def test_basic_arithmetic(self):
        expr, vs = eval_z3("x + y * 2", use_integers=True)
        assert "x" in vs and "y" in vs

    def test_modulo(self):
        expr, vs = eval_z3("x % 2", use_integers=True)
        assert "x" in vs

    def test_comparison(self):
        expr, vs = eval_z3("x == y", use_integers=True)
        assert is_bool(expr)

    def test_hex_literal(self):
        expr, vs = eval_z3("0x10", use_integers=True)
        assert simplify(expr).as_long() == 16

    def test_bitwise_rejected(self):
        with pytest.raises(ValueError, match="integer mode"):
            eval_z3("x & y", use_integers=True)

    def test_shift_rejected(self):
        with pytest.raises(ValueError, match="integer mode"):
            eval_z3("x << 2", use_integers=True)

    def test_bitnot_rejected(self):
        with pytest.raises(ValueError, match="integer mode"):
            eval_z3("~x", use_integers=True)

    def test_number_theory_predicate(self):
        """x*(x+1) % 2 == 0 should be provable in integer mode."""
        from z3 import Solver, Not, sat, unsat
        expr, vs = eval_z3("(x * (x + 1)) % 2 == 0", use_integers=True)
        assert is_bool(expr)
        s = Solver()
        s.add(Not(expr))
        assert s.check() == unsat  # always true


# ---------------------------------------------------------------------------
# Bit-width parameter
# ---------------------------------------------------------------------------

class TestBitWidth:

    def test_8bit(self):
        """255 + 1 should wrap to 0 in 8-bit mode."""
        expr, vs = eval_z3("255 + 1", bit_width=8)
        assert simplify(expr).as_long() == 0

    def test_16bit(self):
        expr, vs = eval_z3("0xffff + 1", bit_width=16)
        assert simplify(expr).as_long() == 0


# ---------------------------------------------------------------------------
# Signed vs unsigned
# ---------------------------------------------------------------------------

class TestSignedness:

    def test_unsigned_comparison(self):
        """In unsigned 8-bit, 255 > 0 is always true."""
        from z3 import Solver, Not, unsat
        expr, vs = eval_z3("x >= 0", bit_width=8, signed=False)
        s = Solver()
        s.add(Not(expr))
        assert s.check() == unsat  # always true for unsigned


# ---------------------------------------------------------------------------
# Integration: the shared parser produces same results as old consumers
# ---------------------------------------------------------------------------

class TestVerifierIntegration:

    def test_xor_identity(self):
        """(x | y) - (x & y) == x ^ y is an MBA identity."""
        from z3 import Solver, Not, unsat
        lhs, _ = eval_z3("(x | y) - (x & y)")
        rhs, _ = eval_z3("x ^ y")
        s = Solver()
        s.add(Not(lhs == rhs))
        assert s.check() == unsat

    def test_not_identity(self):
        """~x == x ^ 0xFFFFFFFF for 32-bit."""
        from z3 import Solver, Not, unsat
        lhs, _ = eval_z3("~x", bit_width=32)
        rhs, _ = eval_z3("x ^ 0xFFFFFFFF", bit_width=32)
        s = Solver()
        s.add(Not(lhs == rhs))
        assert s.check() == unsat


class TestPredicateIntegration:

    def test_always_true(self):
        from d810g_engine.opaque.predicate import classify_predicate
        result = classify_predicate("x == x", bit_width=32)
        assert result["classification"] == "always_true"

    def test_always_false(self):
        from d810g_engine.opaque.predicate import classify_predicate
        result = classify_predicate("(x & 1) == 2", bit_width=32)
        assert result["classification"] == "always_false"

    def test_hex_predicate(self):
        from d810g_engine.opaque.predicate import classify_predicate
        result = classify_predicate("(x & 0xff) == 0x41", bit_width=32)
        assert result["classification"] == "dynamic"
