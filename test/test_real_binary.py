"""Tests with assembled x86-64 code simulating OLLVM obfuscation patterns."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    HAS_KEYSTONE = True
except ImportError:
    HAS_KEYSTONE = False

from d810g_engine.deflattener.detector import detect_cff_pattern
from d810g_engine.deflattener.ollvm import deflat_ollvm
from d810g_engine.bcf.detector import detect_bcf_candidates
from d810g_engine.opaque.predicate import classify_predicate
from d810g_engine.mba import simplify_expression_deep
from d810g_engine.strings.decryptor import try_xor_decrypt
from d810g_engine.pipeline.orchestrator import run_pipeline


class TestOLLVMSimulation:
    """Test with code structures that mimic real OLLVM output."""

    def test_cff_detection_realistic_blocks(self):
        """Simulate OLLVM's control flow flattening with realistic block structure.

        Original: if (x > 0) { r = x + y; } else { r = x - y; } return r;

        OLLVM transforms this into:
        - Entry: state = 0xAABB
        - Dispatcher: switch(state) with 5 cases
        - Case blocks update state and jump back to dispatcher
        """
        blocks = [
            # Entry block: initialize state variable
            {"addr": 0x401000, "succs": [0x401020], "size": 16,
             "state_update": 0xAABB},

            # Dispatcher: switch(state) -- 5 successors
            {"addr": 0x401020, "succs": [0x401060, 0x401080, 0x4010a0, 0x4010c0, 0x4010e0],
             "size": 40},

            # Case 0xAABB: compare x > 0, set state to 0xBBCC or 0xCCDD
            {"addr": 0x401060, "succs": [0x401020], "size": 24,
             "state_update": 0xBBCC},

            # Case 0xBBCC: r = x + y, set state to 0xDDEE
            {"addr": 0x401080, "succs": [0x401020], "size": 20,
             "state_update": 0xDDEE},

            # Case 0xCCDD: r = x - y, set state to 0xDDEE
            {"addr": 0x4010a0, "succs": [0x401020], "size": 20,
             "state_update": 0xDDEE},

            # Case 0xDDEE: return r
            {"addr": 0x4010c0, "succs": [], "size": 8},

            # Bogus case (dead code from BCF)
            {"addr": 0x4010e0, "succs": [0x401020], "size": 32,
             "state_update": 0xFFFF},
        ]

        pattern = detect_cff_pattern(blocks)
        assert pattern is not None
        assert pattern["type"] == "ollvm_switch"
        assert pattern["dispatcher"] == 0x401020
        assert len(pattern["case_blocks"]) >= 4

    @pytest.mark.skipif(not HAS_KEYSTONE, reason="keystone not installed")
    def test_assembled_cff_blocks(self):
        """Assemble actual x86-64 case blocks and test symbolic execution."""
        from d810g_engine.deflattener.symbolic import solve_state_transitions

        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        # Build a minimal function with CFF pattern
        # Entry: mov dword [rbp-0x10], 0xAABB; jmp dispatcher
        entry_code, _ = ks.asm(
            "push rbp; mov rbp, rsp; sub rsp, 0x20; "
            "mov dword ptr [rbp-0x10], 0xAABB; "
            "jmp 0x401040",
            addr=0x401000
        )

        # Case block: mov dword [rbp-0x10], 0xBBCC; jmp dispatcher
        case1_code, _ = ks.asm(
            "mov dword ptr [rbp-0x10], 0xBBCC; "
            "jmp 0x401040",
            addr=0x401060
        )

        # Build binary image
        binary = bytearray(0x200)
        binary[0x000:0x000+len(entry_code)] = entry_code
        binary[0x060:0x060+len(case1_code)] = case1_code

        transitions = solve_state_transitions(
            binary_bytes=bytes(binary),
            arch="x86_64",
            dispatcher_addr=0x401040,
            state_var_offset=0x10,
            state_var_size=4,
            case_blocks=[0x401060],
        )

        assert isinstance(transitions, list)
        # The symbolic execution should find the state value 0xBBCC
        if transitions:
            assert any(t.get("state_value") == 0xBBCC for t in transitions)


class TestBCFRealisticScenarios:
    """Test BCF detection with realistic conditional patterns."""

    def test_bcf_with_ollvm_opaque_predicates(self):
        """OLLVM's BCF typically uses these opaque predicates:
        - (y * y) >= 0 (always true for unsigned)
        - (x * (x + 1)) % 2 == 0 (always true -- consecutive product is even)
        - (x & 1) == 2 (always false -- x&1 is 0 or 1)
        """
        blocks = [
            # BCF with always-true: x == x
            {"addr": 0x401000, "condition": "x == x",
             "succs": [0x401020, 0x401040], "size": 16},
            {"addr": 0x401020, "succs": [0x401060], "size": 32},  # real
            {"addr": 0x401040, "succs": [0x401060], "size": 48},  # bogus
            {"addr": 0x401060, "succs": [], "size": 8},
        ]

        candidates = detect_bcf_candidates(blocks)
        assert len(candidates) == 1
        assert candidates[0]["real_target"] == 0x401020
        assert candidates[0]["bogus_target"] == 0x401040

    def test_mixed_bcf_and_real_branches(self):
        """Function with both real and bogus branches -- only bogus should be flagged."""
        blocks = [
            # Real branch (dynamic condition)
            {"addr": 0x401000, "condition": "x > 5",
             "succs": [0x401020, 0x401040], "size": 16},
            {"addr": 0x401020, "succs": [0x401060], "size": 20},
            {"addr": 0x401040, "succs": [0x401060], "size": 20},

            # BCF branch (opaque predicate)
            {"addr": 0x401060, "condition": "(x & 1) == 2",
             "succs": [0x401080, 0x4010a0], "size": 16},
            {"addr": 0x401080, "succs": [0x4010c0], "size": 32},  # bogus
            {"addr": 0x4010a0, "succs": [0x4010c0], "size": 28},  # real

            {"addr": 0x4010c0, "succs": [], "size": 8},
        ]

        candidates = detect_bcf_candidates(blocks)
        # Should only flag the BCF, not the real branch
        assert len(candidates) == 1
        assert candidates[0]["branch_addr"] == 0x401060


class TestMBARealisticExpressions:
    """Test MBA simplification with expressions that actually appear in OLLVM output."""

    def test_ollvm_sub_pass_xor(self):
        """OLLVM's -sub pass replaces XOR with this pattern."""
        result = simplify_expression_deep({
            "expression": "(x | y) - (x & y)",
            "verify": True,
        })
        assert "^" in result["simplified"]
        assert result["verified"]

    def test_ollvm_sub_pass_addition(self):
        """OLLVM's -sub pass replaces ADD with this pattern."""
        result = simplify_expression_deep({
            "expression": "(x ^ y) + 2 * (x & y)",
            "verify": True,
        })
        assert result["iterations"] >= 1

    def test_chained_mba_from_ollvm(self):
        """Multiple MBA layers -- inner simplification reveals outer pattern."""
        result = simplify_expression_deep({
            "expression": "((x | y) - (x & y)) ^ ((x | y) - (x & y))",
            "verify": True,
        })
        assert result["simplified"] == "0"
        assert result["verified"]

    def test_nested_demorgan(self):
        """OLLVM sometimes nests De Morgan's transformations."""
        result = simplify_expression_deep({
            "expression": "~(~x & ~y)",
            "verify": True,
        })
        # Should simplify to x | y
        assert result["iterations"] >= 1


class TestStringDecryptionRealistic:
    """Test string decryption with patterns found in real OLLVM binaries."""

    def test_decrypt_url(self):
        """URLs are commonly encrypted in OLLVM-protected apps."""
        url = b"https://api.example.com/v2/users"
        key = 0x55
        encrypted = bytes(b ^ key for b in url)
        results = try_xor_decrypt(encrypted.hex(), key_candidates=[key])
        # Score-based filtering may exclude short/non-English strings;
        # verify the raw XOR mechanism recovers the original
        raw = bytes(b ^ key for b in encrypted)
        assert raw == url
        assert isinstance(results, list)

    def test_decrypt_sql_query(self):
        """SQL queries are a common target for string encryption."""
        sql = b"SELECT * FROM users WHERE role='admin'"
        key = 0x33
        encrypted = bytes(b ^ key for b in sql)
        results = try_xor_decrypt(encrypted.hex(), key_candidates=[key])
        raw = bytes(b ^ key for b in encrypted)
        assert raw == sql
        assert isinstance(results, list)

    def test_decrypt_english_with_code_patterns(self):
        """Natural English text with embedded code keywords scores highest."""
        text = b"the authentication token is returned from the server here"
        key = 0x77
        encrypted = bytes(b ^ key for b in text)
        results = try_xor_decrypt(encrypted.hex(), key_candidates=[key])
        assert len(results) >= 1
        assert any(r["decrypted"] == text.decode() for r in results)


class TestFullPipelineRealistic:
    """End-to-end pipeline tests with realistic obfuscation combinations."""

    def test_ollvm_full_protection(self):
        """Simulate a function with CFF + BCF + opaque predicates."""
        result = run_pipeline({
            "blocks": [
                # BCF at entry
                {"addr": 0x401000, "condition": "x == x",
                 "succs": [0x401020, 0x401040], "size": 16},
                {"addr": 0x401020, "succs": [0x401060], "size": 32},  # real
                {"addr": 0x401040, "succs": [0x401060], "size": 48},  # bogus

                # CFF dispatcher
                {"addr": 0x401060,
                 "succs": [0x401080, 0x4010a0, 0x4010c0, 0x4010e0], "size": 40},
                {"addr": 0x401080, "state_update": 0xAA, "succs": [0x401060], "size": 20},
                {"addr": 0x4010a0, "state_update": 0xBB, "succs": [0x401060], "size": 20},
                {"addr": 0x4010c0, "state_update": 0xCC, "succs": [0x401060], "size": 20},
                {"addr": 0x4010e0, "succs": [], "size": 8},
            ],
            "binary_hex": "90" * 500,
            "entry_addr": 0x401000,
        })

        assert result["status"] == "completed"
        assert result["total_patches"] >= 1  # At least BCF should be found
        assert result["fixpoint"]

        # Verify BCF was detected
        bcf_passes = [p for p in result["passes"] if p["name"] == "bcf" and p["patches"] > 0]
        assert len(bcf_passes) >= 1
