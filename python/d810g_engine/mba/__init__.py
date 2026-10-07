"""MBA simplification module."""

from __future__ import annotations
from pathlib import Path
from typing import Any

from d810g_engine.log import get_logger
from d810g_engine.mba.rules import load_rules
from d810g_engine.mba.matcher import ASTNode, parse_expr, match_rule, Op
from d810g_engine.mba.verifier import verify_equivalence

logger = get_logger("mba")


_RULES_DIR = Path(__file__).parent.parent.parent.parent / "data" / "rules"


_COMPARE_OPS = {"==", "!=", "<", "<=", ">", ">="}


def _has_comparison(expr: str) -> bool:
    """Check if an expression string contains comparison operators."""
    for op in _COMPARE_OPS:
        if op in expr:
            return True
    return False


def simplify_expression(params: dict[str, Any]) -> dict[str, Any]:
    """Simplify an MBA expression using loaded rules."""
    expr_str = params["expression"]
    rules_file = params.get("rules", "all")
    verify = params.get("verify", True)

    if rules_file == "all":
        rules = []
        for f in sorted(_RULES_DIR.glob("*.json")):
            rules.extend(load_rules(f))
    else:
        rules = load_rules(_RULES_DIR / rules_file)
    expr_ast = parse_expr(expr_str)

    for rule in rules:
        result = match_rule(expr_ast, rule)
        if result is not None:
            simplified = _ast_to_str(result)
            verified = False
            if verify and simplified != expr_str:
                if _has_comparison(expr_str) or _has_comparison(simplified):
                    verified = False  # can't verify mixed boolean/arithmetic
                else:
                    try:
                        verified = verify_equivalence(expr_str, simplified)
                    except Exception:
                        verified = False
            elif verify:
                verified = True
            logger.info("Matched rule %s: %s -> %s (verified=%s)",
                        rule.id, expr_str, simplified, verified)
            return {
                "original": expr_str,
                "simplified": simplified,
                "rule_id": rule.id,
                "verified": verified,
            }

    logger.debug("No rule matched: %s", expr_str)
    return {"original": expr_str, "simplified": expr_str, "rule_id": None, "verified": True}


def _ast_to_str(node: ASTNode) -> str:
    if node.op == Op.VAR:
        return node.name
    if node.op == Op.CONST:
        return str(node.value)
    op_map = {
        Op.ADD: "+", Op.SUB: "-", Op.MUL: "*",
        Op.AND: "&", Op.OR: "|", Op.XOR: "^",
        Op.SHL: "<<", Op.SHR: ">>",
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


def simplify_expression_deep(params: dict[str, Any]) -> dict[str, Any]:
    """Iteratively simplify an MBA expression until no more rules apply.

    Applies all rule files in sequence, repeating until fixpoint or max_iterations.
    Returns the full simplification chain for transparency.
    """
    expr_str = params["expression"]
    max_iterations = params.get("max_iterations", 10)
    verify = params.get("verify", True)

    # Load ALL rule files
    all_rules = []
    for rules_file in sorted(_RULES_DIR.glob("*.json")):
        all_rules.extend(load_rules(rules_file))

    chain = []  # list of {step, rule_id, before, after}
    current = expr_str

    for iteration in range(max_iterations):
        current_ast = parse_expr(current)

        # Try to simplify any sub-expression, not just the root
        result_ast, applied_rule = _simplify_recursive(current_ast, all_rules)

        if applied_rule is not None:
            new_expr = _ast_to_str(result_ast)
            if new_expr != current:
                chain.append({
                    "step": iteration + 1,
                    "rule_id": applied_rule.id,
                    "before": current,
                    "after": new_expr,
                })
                current = new_expr
                continue

        # No simplification found — fixpoint reached
        break

    if current == expr_str:
        verified = True
    elif verify:
        if _has_comparison(expr_str) or _has_comparison(current):
            verified = False  # can't verify mixed boolean/arithmetic
        else:
            try:
                verified = verify_equivalence(expr_str, current)
            except Exception:
                verified = False
    else:
        verified = False

    return {
        "original": expr_str,
        "simplified": current,
        "iterations": len(chain),
        "chain": chain,
        "verified": verified,
        "fixpoint": len(chain) < max_iterations,
    }


def _simplify_recursive(node: ASTNode, rules: list) -> tuple[ASTNode, Any]:
    """Try to simplify any node in the AST tree (bottom-up).

    First tries to simplify children, then the current node.
    Returns (simplified_node, rule_that_matched) or (original_node, None).
    """
    # First, try to simplify children (bottom-up)
    if node.children:
        new_children = []
        for i, child in enumerate(node.children):
            simplified_child, rule = _simplify_recursive(child, rules)
            if rule is not None:
                # A child was simplified — rebuild this node and return
                new_children.append(simplified_child)
                new_children.extend(node.children[i + 1:])
                return ASTNode(
                    op=node.op,
                    children=new_children,
                    name=node.name,
                    value=node.value,
                ), rule
            new_children.append(child)
        node = ASTNode(op=node.op, children=new_children, name=node.name, value=node.value)

    # Then try to simplify the current node
    for rule in rules:
        result = match_rule(node, rule)
        if result is not None:
            return result, rule

    return node, None


def register_handlers(server: Any) -> None:
    """Register MBA simplification handlers on the server."""
    server.register("mba.simplify", simplify_expression)
    server.register("mba.simplify_deep", simplify_expression_deep)
