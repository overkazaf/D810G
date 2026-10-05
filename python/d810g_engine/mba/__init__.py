"""MBA simplification module."""

from __future__ import annotations
from pathlib import Path
from typing import Any

from d810g_engine.mba.rules import load_rules
from d810g_engine.mba.matcher import ASTNode, parse_expr, match_rule, Op
from d810g_engine.mba.verifier import verify_equivalence


_RULES_DIR = Path(__file__).parent.parent.parent.parent / "data" / "rules"


def simplify_expression(params: dict[str, Any]) -> dict[str, Any]:
    """Simplify an MBA expression using loaded rules."""
    expr_str = params["expression"]
    rules_file = params.get("rules", "mba_basic.json")
    verify = params.get("verify", True)

    rules = load_rules(_RULES_DIR / rules_file)
    expr_ast = parse_expr(expr_str)

    for rule in rules:
        result = match_rule(expr_ast, rule)
        if result is not None:
            simplified = _ast_to_str(result)
            verified = False
            if verify:
                verified = verify_equivalence(expr_str, simplified)
            return {
                "original": expr_str,
                "simplified": simplified,
                "rule_id": rule.id,
                "verified": verified,
            }

    return {"original": expr_str, "simplified": expr_str, "rule_id": None, "verified": True}


def _ast_to_str(node: ASTNode) -> str:
    if node.op == Op.VAR:
        return node.name
    if node.op == Op.CONST:
        return str(node.value)
    op_map = {
        Op.ADD: "+", Op.SUB: "-", Op.MUL: "*",
        Op.AND: "&", Op.OR: "|", Op.XOR: "^",
    }
    if node.op == Op.NOT:
        return f"~{_ast_to_str(node.children[0])}"
    if node.op == Op.NEG:
        return f"-{_ast_to_str(node.children[0])}"
    if node.op in op_map and len(node.children) == 2:
        left = _ast_to_str(node.children[0])
        right = _ast_to_str(node.children[1])
        return f"({left} {op_map[node.op]} {right})"
    return "?"


def register_handlers(server) -> None:
    server.register("mba.simplify", simplify_expression)
