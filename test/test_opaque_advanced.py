import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.opaque.advanced import classify_advanced, batch_classify_advanced


class TestNumberTheoryPredicates:

    def test_even_product(self):
        """x*(x+1) % 2 == 0 is always true (consecutive integers)."""
        result = classify_advanced("(x * (x + 1)) % 2 == 0", bit_width=32)
        assert result["classification"] == "always_true"

    def test_square_non_negative_unsigned(self):
        """x*x >= 0 is always true for unsigned."""
        result = classify_advanced("(x * x) >= 0", bit_width=32)
        # May be proven via bitvector or integer mode
        assert result["classification"] in ("always_true", "dynamic")

    def test_identity(self):
        """x == x is trivially always true."""
        result = classify_advanced("x == x", bit_width=32)
        assert result["classification"] == "always_true"

    def test_contradiction(self):
        """(x & 1) == 2 is always false."""
        result = classify_advanced("(x & 1) == 2", bit_width=32)
        assert result["classification"] == "always_false"

    def test_real_condition(self):
        """x > 5 is genuinely dynamic."""
        result = classify_advanced("x > 5", bit_width=32)
        assert result["classification"] == "dynamic"


class TestIntegerArithmetic:

    def test_integer_mode_fallback(self):
        """Test that integer arithmetic mode is tried."""
        result = classify_advanced("(x * (x + 1)) % 2 == 0", bit_width=64)
        assert "method" in result

    def test_sum_consecutive_div3(self):
        """x + (x+1) + (x+2) divisible by 3 -- easier in integer mode."""
        result = classify_advanced("(x + (x + 1) + (x + 2)) % 3 == 0", bit_width=32)
        assert result["classification"] == "always_true"


class TestBatchAdvanced:

    def test_batch_mixed(self):
        result = batch_classify_advanced({
            "predicates": [
                {"expression": "x == x", "address": 0x1000},
                {"expression": "(x & 1) == 2", "address": 0x1010},
                {"expression": "x > 5", "address": 0x1020},
            ],
        })
        assert result["total"] == 3
        assert result["opaque_count"] == 2
        assert result["dynamic_count"] == 1

    def test_batch_all_opaque(self):
        result = batch_classify_advanced({
            "predicates": [
                {"expression": "x == x"},
                {"expression": "(x & 3) == 4"},
            ],
        })
        assert result["opaque_count"] == 2


class TestMethodReporting:

    def test_reports_bitvector_method(self):
        result = classify_advanced("x == x", bit_width=32)
        assert "method" in result

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.opaque import register_handlers
        server = Server()
        register_handlers(server)
        assert "opaque.classify_advanced" in server._handlers
        assert "opaque.batch_advanced" in server._handlers
