"""Scenarios from "Deconstructing Obfuscation" (arXiv:2505.19887).

The paper finds LLMs weakest on instruction substitution (IS) and prone to
five error classes: predicate misjudgement, CFF case mis-mapping, mistaking
a CFF dispatcher / BCF for a real loop, arithmetic slips and fabricated
constants.  Each test below pins down one of those analysis scenarios so the
deterministic engine (rules + Z3) can be checked against them.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.mba import simplify_expression_deep
from d810g_engine.mba.matcher import parse_expr
from d810g_engine.mba.verifier import verify_equivalence
from d810g_engine.opaque.advanced import classify_advanced
from d810g_engine.opaque.predicate import classify_predicate


def _deep(expr: str) -> dict:
    return simplify_expression_deep({"expression": expr, "max_iterations": 30})


# ---------------------------------------------------------------------------
# Scenario 1 -- paper opaque predicate: x*(x-1) is always even
# ---------------------------------------------------------------------------

class TestPaperOpaquePredicate:

    @pytest.mark.parametrize("bits", [8, 16, 32, 64])
    def test_consecutive_product_even(self, bits):
        r = classify_predicate("((x * (x - 1)) & 1) == 0", bit_width=bits)
        assert r["classification"] == "always_true"

    def test_unparenthesized_form(self):
        """The shared parser binds ``&`` tighter than ``==`` (unlike C), so the
        paper's unparenthesized spelling parses as the intended predicate."""
        r = classify_predicate("(x * (x - 1)) & 1 == 0")
        assert r["classification"] == "always_true"

    def test_negated_is_always_false(self):
        r = classify_predicate("((x * (x - 1)) & 1) != 0")
        assert r["classification"] == "always_false"

    def test_advanced_reports_bitvector_method(self):
        r = classify_advanced("((x * (x - 1)) & 1) == 0")
        assert r["classification"] == "always_true"
        assert r["method"] == "bitvector"


# ---------------------------------------------------------------------------
# Scenario 2 -- MBA-disguised predicate: (x|(x-1)) - (x^(x-1)) == x & (x-1)
# ---------------------------------------------------------------------------

class TestMBAOpaquePredicate:
    """``(x | y) - (x ^ y) == x & y`` with ``y = x - 1``, i.e. ``x`` with its
    lowest set bit cleared.  Whether ``< 0`` is opaque depends on signedness:

    * unsigned: ``u < 0`` is trivially false -> opaque (always false)
    * signed:   NOT opaque -- x = 0xC0000000 gives 0x80000000 < 0 (true)
    """

    EXPR = "((x | (x - 1)) - (x ^ (x - 1))) < 0"
    GE_EXPR = "(x | (x - 1)) >= (x ^ (x - 1))"

    def test_unsigned_always_false(self):
        r = classify_predicate(self.EXPR, signed=False)
        assert r["classification"] == "always_false"

    def test_signed_is_dynamic(self):
        r = classify_predicate(self.EXPR, signed=True)
        assert r["classification"] == "dynamic"

    def test_signed_counterexample(self):
        from z3 import BitVecVal, simplify
        x = BitVecVal(0xC0000000, 32)
        lhs = simplify((x | (x - 1)) - (x ^ (x - 1)))
        assert lhs.as_long() == 0x80000000  # negative as int32

    def test_ge_form_unsigned_always_true(self):
        r = classify_predicate(self.GE_EXPR, signed=False)
        assert r["classification"] == "always_true"

    def test_ge_form_signed_is_dynamic(self):
        # x = 0xC0000000: OR = 0xFFFFFFFF (-1) < XOR = 0x7FFFFFFF
        r = classify_predicate(self.GE_EXPR, signed=True)
        assert r["classification"] == "dynamic"

    def test_unsigned_64bit(self):
        r = classify_predicate(self.GE_EXPR, bit_width=64, signed=False)
        assert r["classification"] == "always_true"

    def test_difference_simplifies_to_and(self):
        r = _deep("(x | (x - 1)) - (x ^ (x - 1))")
        assert parse_expr(r["simplified"]) == parse_expr("x & (x - 1)")
        assert r["verified"] is True


# ---------------------------------------------------------------------------
# Scenario 3 -- instruction substitution identities (OLLVM Substitution.cpp)
# ---------------------------------------------------------------------------

# (obfuscated, expected).  R is the per-instruction random constant OLLVM
# draws for the *Rand variants -- written in hex as it appears in binaries.
IS_CASES = [
    # common MBA forms named in the paper discussion
    ("(a ^ b) + 2 * (a & b)", "a + b"),
    ("(a ^ b) - 2 * (~a & b)", "a - b"),
    ("(a & b) + (a ^ b)", "a | b"),
    # OLLVM addNeg / addDoubleNeg / addRand / addRand2
    ("a - (-b)", "a + b"),
    ("-(-a + (-b))", "a + b"),
    ("((a + 0x5A17C3E9) + b) - 0x5A17C3E9", "a + b"),
    ("((a - 0x5A17C3E9) + b) + 0x5A17C3E9", "a + b"),
    # OLLVM subNeg / subRand / subRand2
    ("a + (-b)", "a - b"),
    ("((a + 0x5A17C3E9) - b) - 0x5A17C3E9", "a - b"),
    ("((a - 0x5A17C3E9) - b) + 0x5A17C3E9", "a - b"),
    # OLLVM andSubstitution / andSubstitutionRand
    ("(a ^ ~b) & a", "a & b"),
    ("~(~a | ~b) & (0x5A17C3E9 | ~0x5A17C3E9)", "a & b"),
    # OLLVM orSubstitution / orSubstitutionRand
    ("(a & b) | (a ^ b)", "a | b"),
    ("(((~a & 0x5A17C3E9) | (a & ~0x5A17C3E9)) ^ ((~b & 0x5A17C3E9) | (b & ~0x5A17C3E9)))"
     " | (~(~a | ~b) & (0x5A17C3E9 | ~0x5A17C3E9))", "a | b"),
    # OLLVM xorSubstitution / xorSubstitutionRand
    ("(~a & b) | (a & ~b)", "a ^ b"),
    ("((~a & 0x5A17C3E9) | (a & ~0x5A17C3E9)) ^ ((~b & 0x5A17C3E9) | (b & ~0x5A17C3E9))",
     "a ^ b"),
]


class TestInstructionSubstitution:

    @pytest.mark.parametrize("obf,expected", IS_CASES, ids=[c[0] for c in IS_CASES])
    def test_identity_holds(self, obf, expected):
        for bits in (32, 64):
            assert verify_equivalence(obf, expected, bit_width=bits)

    @pytest.mark.parametrize("obf,expected", IS_CASES, ids=[c[0] for c in IS_CASES])
    def test_simplifies_back(self, obf, expected):
        r = _deep(obf)
        assert parse_expr(r["simplified"]) == parse_expr(expected), r["chain"]
        assert r["verified"] is True

    def test_hex_literal_parsed_as_constant(self):
        from d810g_engine.mba.matcher import ASTNode, Op
        node = parse_expr("a ^ 0xBAAAD0BF")
        assert node.children[1] == ASTNode(Op.CONST, value=0xBAAAD0BF)


# ---------------------------------------------------------------------------
# Scenario 4 -- the paper's test function after IS
# ---------------------------------------------------------------------------

C = "0xBAAAD0BF"

# Original arm of `switch (n % 4)` -> one IS-obfuscated spelling of it.
PAPER_ARMS = {
    "mod0": (
        f"(n | {C}) * (2 ^ n)",
        f"((n & {C}) | (n ^ {C})) * ((~2 & n) | (2 & ~n))",
    ),
    "mod1": (
        f"(n & {C}) * (3 + n)",
        f"((n ^ ~{C}) & n) * ((3 ^ n) + 2 * (3 & n))",
    ),
    "mod2": (
        f"(n ^ {C}) * (4 | n)",
        f"((~n & {C}) | (n & ~{C})) * ((4 & n) | (4 ^ n))",
    ),
    "mod3": (
        f"(n + {C}) * (5 & n)",
        f"((n ^ {C}) + 2 * (n & {C})) * ((5 ^ ~n) & 5)",
    ),
    # OLLVM *Rand variants with a second random constant
    "mod3_rand": (
        f"(n + {C}) * (5 & n)",
        f"(((n - 0x1F2E3D4C) + {C}) + 0x1F2E3D4C) * (~(~5 | ~n) & (0x77 | ~0x77))",
    ),
    "mod1_neg": (
        f"(n & {C}) * (3 + n)",
        f"((n ^ ~{C}) & n) * (3 - (-n))",
    ),
}


class TestPaperFunction:

    @pytest.mark.parametrize("arm", sorted(PAPER_ARMS))
    def test_obfuscation_is_sound(self, arm):
        original, obf = PAPER_ARMS[arm]
        assert verify_equivalence(original, obf, bit_width=32)

    @pytest.mark.parametrize("arm", sorted(PAPER_ARMS))
    def test_arm_recovers_original(self, arm):
        original, obf = PAPER_ARMS[arm]
        r = _deep(obf)
        assert parse_expr(r["simplified"]) == parse_expr(original), r["chain"]
        assert r["verified"] is True

    def test_constant_survives_as_value(self):
        """The recovered constant must be the paper's 0xBAAAD0BF, not a
        hallucinated one (cf. the 0xe6c98769 slip reported for LLMs)."""
        _, obf = PAPER_ARMS["mod3"]
        r = _deep(obf)
        assert str(0xBAAAD0BF) in r["simplified"]


# ---------------------------------------------------------------------------
# Scenario 5 -- CFF dispatcher vs. a real loop
# ---------------------------------------------------------------------------

class TestDispatcherVsLoop:

    def _detect(self, blocks):
        from d810g_engine.deflattener.detector import detect_cff_pattern
        return detect_cff_pattern(blocks)

    def test_ollvm_dispatcher_detected(self):
        blocks = [
            {"addr": 0x100, "succs": [0x110, 0x120, 0x130, 0x140]},
            {"addr": 0x110, "state_update": 0x3E1A9F02, "succs": [0x100]},
            {"addr": 0x120, "state_update": 0x9C04B7D1, "succs": [0x100]},
            {"addr": 0x130, "state_update": 0x51F0E6A8, "succs": [0x100]},
            {"addr": 0x140, "succs": []},
        ]
        r = self._detect(blocks)
        assert r is not None and r["dispatcher"] == 0x100

    def test_counting_loop_not_cff(self):
        """for (i = 0; i < n; i++) body;  -- single latch, 2-way header."""
        blocks = [
            {"addr": 0x100, "state_update": 0, "succs": [0x110]},     # i = 0
            {"addr": 0x110, "condition": "i < n", "succs": [0x120, 0x140]},
            {"addr": 0x120, "succs": [0x130]},                         # body
            {"addr": 0x130, "succs": [0x110]},                         # i++
            {"addr": 0x140, "succs": []},
        ]
        assert self._detect(blocks) is None

    def test_switch_in_loop_with_join_not_cff(self):
        """while (i < n) { switch (op[i]) {...} i++; } -- cases reach the
        header via a join block, not directly."""
        blocks = [
            {"addr": 0x100, "condition": "i < n", "succs": [0x110, 0x160]},
            {"addr": 0x110, "succs": [0x120, 0x130, 0x140]},
            {"addr": 0x120, "state_update": 1, "succs": [0x150]},
            {"addr": 0x130, "state_update": 2, "succs": [0x150]},
            {"addr": 0x140, "state_update": 3, "succs": [0x150]},
            {"addr": 0x150, "succs": [0x100]},
            {"addr": 0x160, "succs": []},
        ]
        assert self._detect(blocks) is None

    def test_loop_writing_same_constant_not_cff(self):
        """for (;;) switch (getc()) { case 'a': seen = 1; continue; ... }

        Every case writes the *same* constant and jumps straight back to the
        switch.  A flattened state machine needs distinct state values to
        reach distinct cases, so this is a real loop, not a dispatcher."""
        blocks = [
            {"addr": 0x100, "succs": [0x110, 0x120, 0x130, 0x140]},
            {"addr": 0x110, "state_update": 1, "succs": [0x100]},
            {"addr": 0x120, "state_update": 1, "succs": [0x100]},
            {"addr": 0x130, "state_update": 1, "succs": [0x100]},
            {"addr": 0x140, "succs": []},
        ]
        assert self._detect(blocks) is None

    def test_writes_to_different_variables_not_cff(self):
        """When the block graph says *where* each constant goes (state_var),
        writes scattered over several variables are not a state machine."""
        blocks = [
            {"addr": 0x100, "succs": [0x110, 0x120, 0x130, 0x140]},
            {"addr": 0x110, "state_update": 1, "state_var": "acc", "succs": [0x100]},
            {"addr": 0x120, "state_update": 2, "state_var": "flag", "succs": [0x100]},
            {"addr": 0x130, "state_update": 3, "state_var": "len", "succs": [0x100]},
            {"addr": 0x140, "succs": []},
        ]
        assert self._detect(blocks) is None

    def test_same_state_var_is_cff(self):
        blocks = [
            {"addr": 0x100, "succs": [0x110, 0x120, 0x130, 0x140]},
            {"addr": 0x110, "state_update": 0xA1, "state_var": "stack[-0x14]", "succs": [0x100]},
            {"addr": 0x120, "state_update": 0xB2, "state_var": "stack[-0x14]", "succs": [0x100]},
            {"addr": 0x130, "state_update": 0xC3, "state_var": "stack[-0x14]", "succs": [0x100]},
            {"addr": 0x140, "succs": []},
        ]
        r = self._detect(blocks)
        assert r is not None
        assert r["state_var"] == "stack[-0x14]"

    def test_tigress_indirect_same_constant_not_cff(self):
        """Interpreter loop through a jump table, every handler writes 0."""
        from d810g_engine.deflattener.tigress import detect_tigress_pattern
        blocks = [
            {"addr": 0x100, "has_indirect_jump": True,
             "jump_table": [0x110, 0x120, 0x130], "succs": [0x110, 0x120, 0x130]},
            {"addr": 0x110, "state_update": 0, "succs": [0x100]},
            {"addr": 0x120, "state_update": 0, "succs": [0x100]},
            {"addr": 0x130, "state_update": 0, "succs": [0x100]},
        ]
        assert detect_tigress_pattern(blocks) is None

    def test_bcf_diamond_in_loop_not_cff(self):
        """BCF diamond guarded by the paper predicate inside a loop: the BCF
        pass handles it, the CFF detector must stay quiet."""
        from d810g_engine.bcf.detector import detect_bcf_candidates
        blocks = [
            {"addr": 0x100, "condition": "i < n", "succs": [0x110, 0x150]},
            {"addr": 0x110, "condition": "((x * (x - 1)) & 1) == 0",
             "succs": [0x120, 0x130]},
            {"addr": 0x120, "succs": [0x140]},
            {"addr": 0x130, "state_update": 0xDEAD, "succs": [0x140]},
            {"addr": 0x140, "succs": [0x100]},
            {"addr": 0x150, "succs": []},
        ]
        assert self._detect(blocks) is None
        cands = detect_bcf_candidates(blocks)
        assert len(cands) == 1
        assert cands[0]["real_target"] == 0x120
        assert cands[0]["bogus_target"] == 0x130


# ---------------------------------------------------------------------------
# Scenario 6 -- LLM output verifier
# ---------------------------------------------------------------------------

class TestLLMOutputVerifier:

    def test_equivalent_candidate(self):
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output("(a ^ b) + 2 * (a & b)", "a + b")
        assert r["equivalent"] is True
        assert all(w["result"] == "equivalent" for w in r["widths"].values())
        assert r["suspicious_constants"] == []

    def test_wrong_candidate_gives_counterexample(self):
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output("(a ^ b) - 2 * (~a & b)", "a + b")
        assert r["equivalent"] is False
        w32 = r["widths"]["32"]
        assert w32["result"] == "counterexample"
        cex = w32["counterexample"]
        # replaying the model must expose the mismatch
        assert cex["original_value"] != cex["candidate_value"]
        assert set(cex["inputs"]) == {"a", "b"}

    def test_width_dependent_candidate(self):
        """0xFFFFFFFF is ~0 only in 32 bits -- 64-bit check must catch it."""
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output("~x", "x ^ 0xFFFFFFFF")
        assert r["widths"]["32"]["result"] == "equivalent"
        assert r["widths"]["64"]["result"] == "counterexample"
        assert r["equivalent"] is False

    def test_fabricated_hexspeak_constant(self):
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output(f"(n ^ {C}) + 2 * (n & {C})", "n + 0xDEADBEEF")
        assert r["equivalent"] is False
        flagged = {c["value"]: c for c in r["suspicious_constants"]}
        assert 0xDEADBEEF in flagged
        assert flagged[0xDEADBEEF]["hexspeak"] is True

    def test_arithmetic_slip_constant(self):
        """The paper's LLM produced 0xe6c98769 out of thin air."""
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output(f"(n + {C}) * (5 & n)", "(n + 0xE6C98769) * (5 & n)")
        assert r["equivalent"] is False
        flagged = [c["value"] for c in r["suspicious_constants"]]
        assert flagged == [0xE6C98769]

    def test_known_constant_from_binary_not_flagged(self):
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output("x + y", "x + y + 0xCAFEBABE - 0xCAFEBABE",
                              known_constants=[0xCAFEBABE])
        assert r["equivalent"] is True
        assert r["suspicious_constants"] == []

    def test_hexspeak_in_original_not_flagged(self):
        """0xBAAAD0BF is itself hexspeak-ish but it IS in the original."""
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output(f"((n & {C}) | (n ^ {C}))", f"n | {C}")
        assert r["equivalent"] is True
        assert r["suspicious_constants"] == []

    def test_derived_constants_not_flagged(self):
        """~C, -C and small literals are legitimate folds, not fabrications."""
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output(f"(n ^ {C}) & n", "n & 0x45552F40",  # ~C
                              bit_widths=[32])
        assert r["equivalent"] is True
        assert r["suspicious_constants"] == []
        r = verify_llm_output("x * 3", "(x << 1) + x")
        assert r["suspicious_constants"] == []

    def test_predicate_candidate(self):
        """LLM claims the paper predicate is 'x > 0' -- refuted."""
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output("((x * (x - 1)) & 1) == 0", "x == x")
        assert r["equivalent"] is True
        r = verify_llm_output("((x * (x - 1)) & 1) == 0", "x > 0")
        assert r["equivalent"] is False

    def test_parse_error_reported(self):
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output("a + b", "rotl(a, 3)")
        assert r["equivalent"] is False
        assert "error" in r

    def test_bool_vs_bitvector_mismatch(self):
        from d810g_engine.llm_verify import verify_llm_output
        r = verify_llm_output("a + b", "a == b")
        assert r["equivalent"] is False
        assert "error" in r


class TestVerifyCLI:

    def test_verify_equivalent(self, capsys):
        from d810g_engine.cli import main
        rc = main(["verify", "(a & b) + (a ^ b)", "a | b"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "32-bit: EQUIVALENT" in out
        assert "64-bit: EQUIVALENT" in out

    def test_verify_counterexample_exit_code(self, capsys):
        from d810g_engine.cli import main
        rc = main(["verify", "(a ^ b) - 2 * (~a & b)", "a + b"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "COUNTEREXAMPLE" in out

    def test_verify_flags_constant(self, capsys):
        from d810g_engine.cli import main
        rc = main(["verify", "--constants", "0x1234",
                   "x ^ 0x1234", "x ^ 0xDEADBEEF"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "0xdeadbeef" in out.lower()
        assert "hexspeak" in out.lower()

    def test_verify_json(self, capsys):
        from d810g_engine.cli import main
        main(["verify", "--json", "--bits", "32", "a - (-b)", "a + b"])
        data = json.loads(capsys.readouterr().out)
        assert data["equivalent"] is True
        assert list(data["widths"]) == ["32"]
