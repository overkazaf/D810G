"""Integration tests -- exercise full pipelines across modules."""

import pytest
from pathlib import Path

from d810g_engine.deflattener.detector import detect_cff_pattern
from d810g_engine.mba.matcher import parse_expr, match_rule
from d810g_engine.mba.rules import load_rules
from d810g_engine.mba import simplify_expression
from d810g_engine.opaque.predicate import classify_predicate


RULES_PATH = Path(__file__).parent.parent / "data" / "rules" / "mba_basic.json"


class TestFullMBAPipeline:
    """End-to-end: load rules, parse expression, simplify, verify."""

    def test_xor_simplification(self):
        result = simplify_expression({
            "expression": "(a | b) - (a & b)",
            "rules": "mba_basic.json",
            "verify": True,
        })
        assert result["rule_id"] == "mba_xor_1"
        assert result["verified"] is True

    def test_xor_via_complement(self):
        result = simplify_expression({
            "expression": "(a & ~b) | (~a & b)",
            "rules": "mba_basic.json",
            "verify": True,
        })
        assert result["rule_id"] == "mba_xor_2"
        assert result["verified"] is True

    def test_add_simplification(self):
        result = simplify_expression({
            "expression": "(a | b) + (a & b)",
            "rules": "mba_basic.json",
            "verify": True,
        })
        assert result["rule_id"] == "mba_add_1"
        assert result["verified"] is True

    def test_no_simplification_needed(self):
        result = simplify_expression({
            "expression": "a + b",
            "rules": "mba_basic.json",
        })
        assert result["rule_id"] is None
        assert result["simplified"] == "a + b"


class TestFullOpaquePipeline:
    """End-to-end: classify several predicates."""

    def test_always_true(self):
        result = classify_predicate("x == x", bit_width=32)
        assert result["classification"] == "always_true"

    def test_always_false(self):
        result = classify_predicate("(x & 1) == 2", bit_width=32)
        assert result["classification"] == "always_false"

    def test_dynamic(self):
        result = classify_predicate("x > 5", bit_width=32)
        assert result["classification"] == "dynamic"


class TestFullDeflatPipeline:
    """End-to-end: detect CFF patterns."""

    def test_detect_and_process(self):
        from d810g_engine.deflattener.ollvm import deflat_ollvm
        result = deflat_ollvm({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1010, 0x1020, 0x1030, 0x1040]},
                {"addr": 0x1010, "state_update": 0xAA, "succs": [0x1000]},
                {"addr": 0x1020, "state_update": 0xBB, "succs": [0x1000]},
                {"addr": 0x1030, "state_update": 0xCC, "succs": [0x1000]},
                {"addr": 0x1040, "succs": []},
            ],
            "binary_hex": "90" * 100,
        })
        assert result["status"] == "deobfuscated"
        assert result["pattern"]["type"] == "ollvm_switch"


class TestServerWiring:
    """Verify all handlers register without error."""

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.deflattener import register_handlers as reg_d
        from d810g_engine.mba import register_handlers as reg_m
        from d810g_engine.opaque import register_handlers as reg_o

        server = Server()
        reg_d(server)
        reg_m(server)
        reg_o(server)

        assert "deflat.run" in server._handlers
        assert "mba.simplify" in server._handlers
        assert "opaque.classify" in server._handlers
        assert "opaque.eliminate" in server._handlers
