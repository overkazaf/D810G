import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.mba.rules import load_rules
from d810g_engine.mba.verifier import verify_equivalence

RULES_DIR = Path(__file__).parent.parent / "data" / "rules"


class TestHackersDelightRules:
    """Verify all Hacker's Delight rules with Z3."""

    def test_load_rules(self):
        rules = load_rules(RULES_DIR / "mba_hackers_delight.json")
        assert len(rules) >= 16

    def test_and_via_or_minus_xor(self):
        assert verify_equivalence("(x | y) - (x ^ y)", "x & y", bit_width=32)

    def test_and_via_or_xor_xor(self):
        assert verify_equivalence("(x | y) ^ (x ^ y)", "x & y", bit_width=32)

    def test_or_via_and_plus_xor(self):
        assert verify_equivalence("(x & y) + (x ^ y)", "x | y", bit_width=32)

    def test_or_via_and_or_xor(self):
        assert verify_equivalence("(x & y) | (x ^ y)", "x | y", bit_width=32)

    def test_xor_via_or_and_not_and(self):
        assert verify_equivalence("(x | y) & ~(x & y)", "x ^ y", bit_width=32)

    def test_xor_via_or_xor_and(self):
        assert verify_equivalence("(x | y) ^ (x & y)", "x ^ y", bit_width=32)

    def test_demorgan_or(self):
        assert verify_equivalence("~(~x & ~y)", "x | y", bit_width=32)

    def test_demorgan_and(self):
        assert verify_equivalence("~(~x | ~y)", "x & y", bit_width=32)

    def test_not_via_negation(self):
        assert verify_equivalence("-x - 1", "~x", bit_width=32)

    def test_double_via_addition(self):
        assert verify_equivalence("x + x", "x * 2", bit_width=32)

    def test_neg_via_complement(self):
        assert verify_equivalence("~x + 1", "-x", bit_width=32)

    def test_neg_via_xor_allones(self):
        assert verify_equivalence("(x ^ ~0) + 1", "-x", bit_width=32)

    def test_not_via_negate_plus_one(self):
        assert verify_equivalence("-(x + 1)", "~x", bit_width=32)

    def test_and_via_subtraction(self):
        assert verify_equivalence("x - (x & ~y)", "x & y", bit_width=32)

    def test_or_via_add_minus_and(self):
        assert verify_equivalence("x + y - (x & y)", "x | y", bit_width=32)

    def test_sub_via_complement_grouped(self):
        assert verify_equivalence("x + (~y + 1)", "x - y", bit_width=32)

    def test_sub_via_complement_flat(self):
        assert verify_equivalence("x + ~y + 1", "x - y", bit_width=32)


class TestOLLVMRules:
    """Verify OLLVM-specific substitution rules with Z3."""

    def test_load_rules(self):
        rules = load_rules(RULES_DIR / "mba_ollvm.json")
        assert len(rules) >= 10

    def test_ollvm_add_via_xor_and(self):
        assert verify_equivalence("(x ^ y) + 2 * (x & y)", "x + y", bit_width=32)

    def test_ollvm_and_via_demorgan(self):
        assert verify_equivalence("~(~x | ~y)", "x & y", bit_width=32)

    def test_ollvm_or_via_demorgan(self):
        assert verify_equivalence("~(~x & ~y)", "x | y", bit_width=32)

    def test_ollvm_or_via_and_xor(self):
        assert verify_equivalence("(x & y) | (x ^ y)", "x | y", bit_width=32)

    def test_ollvm_xor_via_masks(self):
        assert verify_equivalence("(~x & y) | (x & ~y)", "x ^ y", bit_width=32)

    def test_ollvm_xor_via_double_demorgan(self):
        assert verify_equivalence("~(~x & ~y) & ~(x & y)", "x ^ y", bit_width=32)

    def test_ollvm_sub_complement_variant(self):
        assert verify_equivalence("~(~x - y)", "x + y", bit_width=32)

    def test_ollvm_add_complement_variant(self):
        assert verify_equivalence("x - (~y)", "x + y + 1", bit_width=32)

    def test_ollvm_add_double_complement(self):
        assert verify_equivalence("~(~x + ~y)", "x + y + 1", bit_width=32)

    def test_ollvm_double_negation(self):
        assert verify_equivalence("~~x", "x", bit_width=32)

    def test_ollvm_and_variant(self):
        assert verify_equivalence("(x ^ ~y) & x", "x & y", bit_width=32)


class TestConstantFoldingRules:
    """Verify constant folding rules."""

    def test_load_rules(self):
        rules = load_rules(RULES_DIR / "mba_constant_folding.json")
        assert len(rules) >= 8

    def test_sub_self(self):
        assert verify_equivalence("x - x", "0", bit_width=32)

    def test_and_idempotent(self):
        assert verify_equivalence("x & x", "x", bit_width=32)

    def test_or_idempotent(self):
        assert verify_equivalence("x | x", "x", bit_width=32)

    def test_xor_self_cancel(self):
        assert verify_equivalence("x ^ x", "0", bit_width=32)

    def test_add_zero(self):
        assert verify_equivalence("x + 0", "x", bit_width=32)

    def test_sub_zero(self):
        assert verify_equivalence("x - 0", "x", bit_width=32)

    def test_mul_one(self):
        assert verify_equivalence("x * 1", "x", bit_width=32)

    def test_mul_zero(self):
        assert verify_equivalence("x * 0", "0", bit_width=32)

    def test_or_zero(self):
        assert verify_equivalence("x | 0", "x", bit_width=32)

    def test_and_allones(self):
        assert verify_equivalence("x & ~0", "x", bit_width=32)
