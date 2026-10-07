"""AST representation and pattern matching for MBA expressions.

NOTE: The tokenizer and recursive-descent parser here return ASTNode trees
(used for structural pattern matching), while the shared parser in
d810g_engine.parser returns Z3 expressions.  A future refactor could unify
the tokenizer and teach the shared parser an AST-output mode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from d810g_engine.mba.rules import Rule


class Op(Enum):
    """AST node operator types for MBA expressions."""

    VAR = auto()
    CONST = auto()
    ADD = auto()
    SUB = auto()
    MUL = auto()
    AND = auto()
    OR = auto()
    XOR = auto()
    NOT = auto()
    NEG = auto()
    SHL = auto()
    SHR = auto()


@dataclass
class ASTNode:
    """AST node for structural pattern matching of MBA expressions."""
    op: Op
    children: list[ASTNode] = field(default_factory=list)
    name: str = ""        # for VAR
    value: int = 0        # for CONST

    def __eq__(self, other):
        if not isinstance(other, ASTNode):
            return NotImplemented
        if self.op != other.op:
            return False
        if self.op == Op.VAR:
            return self.name == other.name
        if self.op == Op.CONST:
            return self.value == other.value
        return self.children == other.children

    def __hash__(self):
        if self.op == Op.VAR:
            return hash((self.op, self.name))
        if self.op == Op.CONST:
            return hash((self.op, self.value))
        return hash((self.op, tuple(self.children)))


# ---------- tokenizer ----------

_OP_CHARS = set("+-*&|^~()")
_SHIFT_CHARS = set("<>")


def _tokenize(expr: str) -> list[str]:
    """Tokenize an expression string into a list of tokens."""
    tokens: list[str] = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c in _OP_CHARS:
            tokens.append(c)
            i += 1
        elif c in _SHIFT_CHARS:
            # Handle << and >> as two-character tokens
            if i + 1 < len(expr) and expr[i + 1] == c:
                tokens.append(c + c)
                i += 2
            else:
                i += 1  # skip lone < or >
        elif c.isdigit():
            j = i
            while j < len(expr) and expr[j].isdigit():
                j += 1
            tokens.append(expr[i:j])
            i = j
        elif c.isalpha() or c == "_":
            j = i
            while j < len(expr) and (expr[j].isalnum() or expr[j] == "_"):
                j += 1
            tokens.append(expr[i:j])
            i = j
        else:
            i += 1  # skip unknown
    return tokens


# ---------- recursive-descent parser ----------
# Precedence (lowest to highest): | < ^ < +/- < & < * < unary(~ -)
# Within each level we scan right-to-left to find the split point,
# which corresponds to left-associative evaluation.

def parse_expr(expr_str: str) -> ASTNode:
    """Parse an infix expression string into an AST."""
    tokens = _tokenize(expr_str)
    node, pos = _parse_or(tokens, 0)
    return node


def _parse_or(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse | (lowest precedence binary op)."""
    left, pos = _parse_xor(tokens, pos)
    while pos < len(tokens) and tokens[pos] == "|":
        pos += 1  # consume |
        right, pos = _parse_xor(tokens, pos)
        left = ASTNode(Op.OR, children=[left, right])
    return left, pos


def _parse_xor(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse ^."""
    left, pos = _parse_add_sub(tokens, pos)
    while pos < len(tokens) and tokens[pos] == "^":
        pos += 1
        right, pos = _parse_add_sub(tokens, pos)
        left = ASTNode(Op.XOR, children=[left, right])
    return left, pos


def _parse_add_sub(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse + and -."""
    left, pos = _parse_and(tokens, pos)
    while pos < len(tokens) and tokens[pos] in ("+", "-"):
        op_tok = tokens[pos]
        pos += 1
        right, pos = _parse_and(tokens, pos)
        op = Op.ADD if op_tok == "+" else Op.SUB
        left = ASTNode(op, children=[left, right])
    return left, pos


def _parse_and(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse &."""
    left, pos = _parse_shift(tokens, pos)
    while pos < len(tokens) and tokens[pos] == "&":
        pos += 1
        right, pos = _parse_shift(tokens, pos)
        left = ASTNode(Op.AND, children=[left, right])
    return left, pos


def _parse_shift(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse << and >>."""
    left, pos = _parse_mul(tokens, pos)
    while pos < len(tokens) and tokens[pos] in ("<<", ">>"):
        op_tok = tokens[pos]
        pos += 1
        right, pos = _parse_mul(tokens, pos)
        op = Op.SHL if op_tok == "<<" else Op.SHR
        left = ASTNode(op, children=[left, right])
    return left, pos


def _parse_mul(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse *."""
    left, pos = _parse_unary(tokens, pos)
    while pos < len(tokens) and tokens[pos] == "*":
        pos += 1
        right, pos = _parse_unary(tokens, pos)
        left = ASTNode(Op.MUL, children=[left, right])
    return left, pos


def _parse_unary(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse unary ~ and -."""
    if pos < len(tokens) and tokens[pos] == "~":
        pos += 1
        operand, pos = _parse_unary(tokens, pos)
        return ASTNode(Op.NOT, children=[operand]), pos
    if pos < len(tokens) and tokens[pos] == "-":
        pos += 1
        operand, pos = _parse_unary(tokens, pos)
        if operand.op == Op.CONST:
            return ASTNode(Op.CONST, value=-operand.value), pos
        return ASTNode(Op.NEG, children=[operand]), pos
    return _parse_atom(tokens, pos)


def _parse_atom(tokens: list[str], pos: int) -> tuple[ASTNode, int]:
    """Parse atoms: parenthesized expressions, variables, constants."""
    if pos >= len(tokens):
        raise ValueError("Unexpected end of expression")

    tok = tokens[pos]
    if tok == "(":
        pos += 1  # consume (
        node, pos = _parse_or(tokens, pos)
        if pos < len(tokens) and tokens[pos] == ")":
            pos += 1  # consume )
        return node, pos
    if tok.isdigit():
        return ASTNode(Op.CONST, value=int(tok)), pos + 1
    if tok[0].isalpha() or tok[0] == "_":
        return ASTNode(Op.VAR, name=tok), pos + 1

    raise ValueError(f"Unexpected token: {tok!r}")


# ---------- pattern matching ----------

def _match(pattern: ASTNode, expr: ASTNode,
           bindings: dict[str, ASTNode]) -> bool:
    """Recursively match a pattern AST against an expression AST.

    Pattern variables (VAR nodes) are wildcards that bind to subtrees.
    If the same variable appears twice, both occurrences must bind to
    structurally equal subtrees.
    """
    if pattern.op == Op.VAR:
        # Pattern variable -- wildcard
        name = pattern.name
        if name in bindings:
            return bindings[name] == expr
        bindings[name] = expr
        return True

    if pattern.op == Op.CONST:
        return expr.op == Op.CONST and expr.value == pattern.value

    # Structural match: same operator, same arity
    if pattern.op != expr.op:
        return False
    if len(pattern.children) != len(expr.children):
        return False
    for pc, ec in zip(pattern.children, expr.children):
        if not _match(pc, ec, bindings):
            return False
    return True


def _substitute(template: ASTNode, bindings: dict[str, ASTNode]) -> ASTNode:
    """Substitute bound variables into a replacement template."""
    if template.op == Op.VAR:
        if template.name in bindings:
            return bindings[template.name]
        return template
    if template.op == Op.CONST:
        return template
    new_children = [_substitute(c, bindings) for c in template.children]
    return ASTNode(template.op, children=new_children, name=template.name,
                   value=template.value)


def match_rule(expr: ASTNode, rule: Rule) -> Optional[ASTNode]:
    """Try to match an expression against a rule.

    Returns the substituted replacement AST if matched, or None.
    If the rule is commutative and the top-level op is binary,
    also tries with top-level children swapped.
    """
    pattern_ast = parse_expr(rule.pattern)
    replacement_ast = parse_expr(rule.replacement)

    # Try direct match
    bindings: dict[str, ASTNode] = {}
    if _match(pattern_ast, expr, bindings):
        return _substitute(replacement_ast, bindings)

    # Try commutative match (swap top-level children of the expression)
    if rule.commutative and len(expr.children) == 2:
        swapped = ASTNode(expr.op, children=[expr.children[1], expr.children[0]])
        bindings = {}
        if _match(pattern_ast, swapped, bindings):
            return _substitute(replacement_ast, bindings)

    return None
