import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.mba import simplify_expression_deep


class TestDeepSimplification:

    def test_single_pass_still_works(self):
        """Simple expression needs only one pass."""
        result = simplify_expression_deep({
            "expression": "(x | y) - (x & y)",
            "verify": True,
        })
        assert result["iterations"] == 1
        assert "^" in result["simplified"]
        assert result["verified"] is True

    def test_nested_simplification(self):
        """Nested MBA: simplifying inner reveals outer pattern."""
        # (x|y)-(x&y) simplifies to x^y first
        # Then the expression containing it might simplify further
        result = simplify_expression_deep({
            "expression": "((x | y) - (x & y)) ^ ((x | y) - (x & y))",
            "verify": True,
        })
        # x^y ^ x^y = 0 (self-XOR)
        assert result["iterations"] >= 1
        assert result["simplified"] == "0" or "0" in result["simplified"]

    def test_no_simplification(self):
        """Normal expression has no MBA pattern."""
        result = simplify_expression_deep({
            "expression": "x + y",
        })
        assert result["iterations"] == 0
        assert result["simplified"] == "x + y"
        assert result["fixpoint"] is True

    def test_chain_recorded(self):
        """Each simplification step is recorded in the chain."""
        result = simplify_expression_deep({
            "expression": "(x | y) - (x & y)",
        })
        assert len(result["chain"]) >= 1
        assert result["chain"][0]["rule_id"] is not None
        assert result["chain"][0]["before"] == "(x | y) - (x & y)"

    def test_max_iterations_respected(self):
        """Should not exceed max_iterations."""
        result = simplify_expression_deep({
            "expression": "(x | y) - (x & y)",
            "max_iterations": 1,
        })
        assert result["iterations"] <= 1

    def test_deep_with_identity(self):
        """x | 0 simplifies to x."""
        result = simplify_expression_deep({
            "expression": "(x | 0) | 0",
            "verify": True,
        })
        assert result["simplified"] == "x"
        assert result["iterations"] >= 1

    def test_handler_registered(self):
        from d810g_engine.server import Server
        from d810g_engine.mba import register_handlers
        server = Server()
        register_handlers(server)
        assert "mba.simplify_deep" in server._handlers


class TestRecursiveSimplification:

    def test_simplify_subexpression(self):
        """Should simplify sub-expressions, not just the root."""
        result = simplify_expression_deep({
            "expression": "a + ((x | y) - (x & y))",
            "verify": False,
        })
        # Inner (x|y)-(x&y) should become x^y
        assert result["iterations"] >= 1
        assert "^" in result["simplified"]
