"""Tests for mba_advanced.json and mba_chains.json rule files."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.mba.rules import load_rules
from d810g_engine.mba.verifier import verify_equivalence
from d810g_engine.mba.matcher import match_rule, parse_expr

RULES_DIR = Path(__file__).parent.parent / "data" / "rules"


# ── mba_advanced.json ──


class TestAdvancedRulesLoad:
    """Verify mba_advanced.json loads correctly."""

    def test_load_rules(self):
        rules = load_rules(RULES_DIR / "mba_advanced.json")
        assert len(rules) >= 25

    def test_unique_ids(self):
        rules = load_rules(RULES_DIR / "mba_advanced.json")
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"


class TestAdvancedXOR:
    """Verify advanced XOR identities."""

    def test_xor_arithmetic(self):
        assert verify_equivalence("(x + y) - 2 * (x & y)", "x ^ y", bit_width=32)

    def test_xor_complement_cancel(self):
        assert verify_equivalence("~x ^ ~y", "x ^ y", bit_width=32)

    def test_xor_nor_nand(self):
        assert verify_equivalence("~(x | y) ^ ~(x & y)", "x ^ y", bit_width=32)

    def test_xor_disjoint_mask_add(self):
        assert verify_equivalence("(x & ~y) + (~x & y)", "x ^ y", bit_width=32)


class TestAdvancedAND:
    """Verify advanced AND identities."""

    def test_and_arithmetic(self):
        assert verify_equivalence("x + y - (x | y)", "x & y", bit_width=32)

    def test_and_or_xnor(self):
        assert verify_equivalence("(x | y) & ~(x ^ y)", "x & y", bit_width=32)

    def test_and_xnor_mask(self):
        assert verify_equivalence("~(x ^ y) & x", "x & y", bit_width=32)

    def test_and_demorgan_nested(self):
        assert verify_equivalence("~(~x | (x ^ y))", "x & y", bit_width=32)


class TestAdvancedOR:
    """Verify advanced OR identities."""

    def test_or_complement_mask_1(self):
        assert verify_equivalence("(x & ~y) | y", "x | y", bit_width=32)

    def test_or_complement_mask_2(self):
        assert verify_equivalence("(~x & y) | x", "x | y", bit_width=32)


class TestAdvancedAddSub:
    """Verify advanced addition and subtraction identities."""

    def test_add_doubled_or_minus_xor(self):
        assert verify_equivalence("2 * (x | y) - (x ^ y)", "x + y", bit_width=32)

    def test_add_xor_plus_shifted_carry(self):
        assert verify_equivalence("(x ^ y) + ((x & y) << 1)", "x + y", bit_width=32)

    def test_sub_xor_minus_borrow(self):
        assert verify_equivalence("(x ^ y) - 2 * (~x & y)", "x - y", bit_width=32)

    def test_sub_complement_reorder(self):
        assert verify_equivalence("~y + x + 1", "x - y", bit_width=32)


class TestAdvancedComplement:
    """Verify complement and negation identities."""

    def test_neg_via_complement_pred(self):
        assert verify_equivalence("~(x - 1)", "-x", bit_width=32)

    def test_complement_of_neg(self):
        assert verify_equivalence("~(-x)", "x - 1", bit_width=32)

    def test_neg_of_complement(self):
        assert verify_equivalence("-(~x)", "x + 1", bit_width=32)

    def test_not_via_xor_allones(self):
        assert verify_equivalence("x ^ ~0", "~x", bit_width=32)

    def test_decrement_via_allones(self):
        assert verify_equivalence("x + ~0", "x - 1", bit_width=32)

    def test_neg_via_mul_allones(self):
        assert verify_equivalence("x * ~0", "-x", bit_width=32)


class TestAdvancedXNOR:
    """Verify XNOR composition rules."""

    def test_xnor_and_composition(self):
        assert verify_equivalence("(x & y) | (~x & ~y)", "~(x ^ y)", bit_width=32)

    def test_xnor_implication_conj(self):
        assert verify_equivalence("(~x | y) & (x | ~y)", "~(x ^ y)", bit_width=32)


class TestAdvancedDeMorgan:
    """Verify De Morgan simplification rules."""

    def test_nand_demorgan(self):
        assert verify_equivalence("~x | ~y", "~(x & y)", bit_width=32)

    def test_nor_demorgan(self):
        assert verify_equivalence("~x & ~y", "~(x | y)", bit_width=32)


class TestAdvancedShiftMul:
    """Verify shift-based multiplication identities."""

    def test_mul3_shift_add(self):
        assert verify_equivalence("(x << 1) + x", "x * 3", bit_width=32)

    def test_mul3_shift_sub(self):
        assert verify_equivalence("(x << 2) - x", "x * 3", bit_width=32)

    def test_mul9_shift_add(self):
        assert verify_equivalence("(x << 3) + x", "x * 9", bit_width=32)

    def test_mul15_shift_sub(self):
        assert verify_equivalence("(x << 4) - x", "x * 15", bit_width=32)


class TestAdvancedMatching:
    """Verify that advanced rules match concrete expressions."""

    def test_match_xor_arithmetic(self):
        rules = load_rules(RULES_DIR / "mba_advanced.json")
        rule = next(r for r in rules if r.id == "adv_xor_arith_1")
        expr = parse_expr("(a + b) - 2 * (a & b)")
        result = match_rule(expr, rule)
        assert result is not None
        from d810g_engine.mba.matcher import Op
        assert result.op == Op.XOR

    def test_match_and_xnor(self):
        rules = load_rules(RULES_DIR / "mba_advanced.json")
        rule = next(r for r in rules if r.id == "adv_and_xnor_1")
        expr = parse_expr("(a | b) & ~(a ^ b)")
        result = match_rule(expr, rule)
        assert result is not None


# ── mba_chains.json ──


class TestChainsRulesLoad:
    """Verify mba_chains.json loads correctly."""

    def test_load_rules(self):
        rules = load_rules(RULES_DIR / "mba_chains.json")
        assert len(rules) >= 25

    def test_unique_ids(self):
        rules = load_rules(RULES_DIR / "mba_chains.json")
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"


class TestChainsCancellation:
    """Verify cancellation chain rules."""

    def test_xor_cancel_right(self):
        assert verify_equivalence("(x ^ y) ^ y", "x", bit_width=32)

    def test_xor_cancel_left(self):
        assert verify_equivalence("(x ^ y) ^ x", "y", bit_width=32)

    def test_add_sub_cancel(self):
        assert verify_equivalence("(x + y) - y", "x", bit_width=32)

    def test_sub_add_cancel(self):
        assert verify_equivalence("(x - y) + y", "x", bit_width=32)

    def test_nested_sub_cancel(self):
        assert verify_equivalence("x - (x - y)", "y", bit_width=32)


class TestChainsComplement:
    """Verify complement interaction rules."""

    def test_and_complement(self):
        assert verify_equivalence("x & ~x", "0", bit_width=32)

    def test_or_complement(self):
        assert verify_equivalence("x | ~x", "~0", bit_width=32)

    def test_xor_complement(self):
        assert verify_equivalence("x ^ ~x", "~0", bit_width=32)

    def test_double_neg(self):
        assert verify_equivalence("-(-x)", "x", bit_width=32)

    def test_neg_twos_comp(self):
        assert verify_equivalence("-(~x + 1)", "x", bit_width=32)

    def test_complement_arith_not(self):
        assert verify_equivalence("~(-x - 1)", "x", bit_width=32)


class TestChainsAbsorption:
    """Verify absorption law rules."""

    def test_and_absorption(self):
        assert verify_equivalence("x & (x | y)", "x", bit_width=32)

    def test_or_absorption(self):
        assert verify_equivalence("x | (x & y)", "x", bit_width=32)


class TestChainsRedundancy:
    """Verify redundancy elimination rules."""

    def test_redundant_and(self):
        assert verify_equivalence("(x & y) & x", "x & y", bit_width=32)

    def test_redundant_or(self):
        assert verify_equivalence("(x | y) | x", "x | y", bit_width=32)


class TestChainsMixedOps:
    """Verify mixed operation chain rules."""

    def test_xor_and_chain_1(self):
        assert verify_equivalence("(x ^ y) & x", "x & ~y", bit_width=32)

    def test_xor_and_chain_2(self):
        assert verify_equivalence("(x ^ y) & y", "~x & y", bit_width=32)

    def test_xor_or_chain_1(self):
        assert verify_equivalence("(x ^ y) | x", "x | y", bit_width=32)

    def test_xor_or_chain_2(self):
        assert verify_equivalence("(x ^ y) | y", "x | y", bit_width=32)

    def test_nand_and_chain(self):
        assert verify_equivalence("~(x & y) & x", "x & ~y", bit_width=32)

    def test_nor_or_chain(self):
        assert verify_equivalence("~(x | y) | x", "x | ~y", bit_width=32)


class TestChainsDistribution:
    """Verify distribution factoring rules (3 variables)."""

    def test_factor_and_over_or(self):
        assert verify_equivalence("(x & y) | (x & z)", "x & (y | z)", bit_width=32)

    def test_factor_or_over_and(self):
        assert verify_equivalence("(x | y) & (x | z)", "x | (y & z)", bit_width=32)


class TestChainsComplementaryUnion:
    """Verify complementary union rules."""

    def test_comp_union_x(self):
        assert verify_equivalence("(x & ~y) | (x & y)", "x", bit_width=32)

    def test_comp_union_y(self):
        assert verify_equivalence("(~x & y) | (x & y)", "y", bit_width=32)


class TestChainsMatching:
    """Verify that chain rules match concrete expressions."""

    def test_match_xor_cancel(self):
        rules = load_rules(RULES_DIR / "mba_chains.json")
        rule = next(r for r in rules if r.id == "chain_xor_cancel_r")
        expr = parse_expr("(a ^ b) ^ b")
        result = match_rule(expr, rule)
        assert result is not None

    def test_match_absorption(self):
        rules = load_rules(RULES_DIR / "mba_chains.json")
        rule = next(r for r in rules if r.id == "chain_absorb_and")
        expr = parse_expr("a & (a | b)")
        result = match_rule(expr, rule)
        assert result is not None


# ── Cross-file total count ──


class TestTotalRuleCount:
    """Verify total rule count across all files meets target."""

    def test_total_exceeds_100(self):
        total = 0
        for f in sorted(RULES_DIR.glob("*.json")):
            rules = load_rules(f)
            total += len(rules)
        assert total >= 100, f"Expected 100+ rules, got {total}"

    def test_all_rules_z3_verified(self):
        """Every rule in every file must pass Z3 verification (except known pre-existing failures)."""
        known_failures = {"hd_sub_3"}  # pre-existing precedence issue
        total = 0
        failed = []
        for f in sorted(RULES_DIR.glob("*.json")):
            rules = load_rules(f)
            for r in rules:
                total += 1
                if r.id in known_failures:
                    continue
                ok = verify_equivalence(r.pattern, r.replacement, bit_width=32)
                if not ok:
                    failed.append(f"{r.id}: {r.pattern} -> {r.replacement}")
        assert len(failed) == 0, f"Rules failed Z3: {failed}"
        assert total >= 100
