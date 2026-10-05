import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.mba.rules import load_rules, Rule
from d810g_engine.mba.matcher import ASTNode, Op, match_rule, parse_expr
from d810g_engine.mba.verifier import verify_equivalence


def test_load_rules():
    rules = load_rules(Path(__file__).parent.parent / "data" / "rules" / "mba_basic.json")
    assert len(rules) >= 10
    assert rules[0].id == "mba_xor_1"


def test_parse_simple_var():
    node = parse_expr("x")
    assert node.op == Op.VAR
    assert node.name == "x"


def test_parse_binary_op():
    node = parse_expr("x + y")
    assert node.op == Op.ADD
    assert len(node.children) == 2


def test_parse_complex_expr():
    node = parse_expr("(x | y) - (x & y)")
    assert node.op == Op.SUB
    assert node.children[0].op == Op.OR
    assert node.children[1].op == Op.AND


def test_match_xor_identity():
    """(x | y) - (x & y) should match mba_xor_1 -> x ^ y"""
    x = ASTNode(Op.VAR, name="x")
    y = ASTNode(Op.VAR, name="y")
    expr = ASTNode(Op.SUB, children=[
        ASTNode(Op.OR, children=[x, y]),
        ASTNode(Op.AND, children=[x, y]),
    ])
    rules = load_rules(Path(__file__).parent.parent / "data" / "rules" / "mba_basic.json")
    result = match_rule(expr, rules[0])
    assert result is not None
    assert result.op == Op.XOR


def test_no_match_on_different_expr():
    x = ASTNode(Op.VAR, name="x")
    y = ASTNode(Op.VAR, name="y")
    expr = ASTNode(Op.ADD, children=[x, y])
    rules = load_rules(Path(__file__).parent.parent / "data" / "rules" / "mba_basic.json")
    result = match_rule(expr, rules[0])
    assert result is None


def test_z3_verify_xor_equivalence():
    assert verify_equivalence("(x | y) - (x & y)", "x ^ y", bit_width=32)


def test_z3_rejects_wrong_equivalence():
    assert not verify_equivalence("(x | y) - (x & y)", "x + y", bit_width=32)


def test_simplify_api():
    from d810g_engine.mba import simplify_expression
    result = simplify_expression({
        "expression": "(x | y) - (x & y)",
        "rules": "mba_basic.json",
        "verify": True,
    })
    assert result["rule_id"] == "mba_xor_1"
    assert result["verified"] is True
    assert "^" in result["simplified"]
