#!/usr/bin/env python3
"""D810G MBA Simplification Demo — concrete examples."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.mba import simplify_expression
from d810g_engine.mba.verifier import verify_equivalence


def banner(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def demo_simplify(expr, desc=""):
    result = simplify_expression({
        "expression": expr,
        "rules": "mba_basic.json",
        "verify": True,
    })
    status = "✅ Z3 verified" if result["verified"] else "⚠️  unverified"
    rule = result["rule_id"] or "no match"
    simplified = result["simplified"]

    if desc:
        print(f"  # {desc}")
    print(f"  Input:      {expr}")
    print(f"  Simplified: {simplified}")
    print(f"  Rule:       {rule}")
    print(f"  Status:     {status}")
    print()


def main():
    banner("D810G Demo: MBA Expression Simplification")

    print("Mixed Boolean-Arithmetic (MBA) expressions are used by obfuscators")
    print("like OLLVM to disguise simple operations as complex formulas.")
    print("D810G automatically detects and simplifies them with Z3 verification.\n")

    print("-" * 60)
    print("Example 1: XOR disguised as OR/AND combination")
    print("-" * 60)
    demo_simplify(
        "(x | y) - (x & y)",
        "OLLVM常用: 把 x^y 展开成 (x|y)-(x&y)"
    )

    print("-" * 60)
    print("Example 2: XOR via complement masking")
    print("-" * 60)
    demo_simplify(
        "(x & ~y) | (~x & y)",
        "另一种XOR变体: (x&~y)|(~x&y)"
    )

    print("-" * 60)
    print("Example 3: Addition disguised as OR + AND")
    print("-" * 60)
    demo_simplify(
        "(x | y) + (x & y)",
        "加法变体: (x|y)+(x&y) = x+y"
    )

    print("-" * 60)
    print("Example 4: Self-XOR (zero constant)")
    print("-" * 60)
    demo_simplify(
        "x ^ x",
        "恒等式: x^x 永远等于0"
    )

    print("-" * 60)
    print("Example 5: OR with zero (identity)")
    print("-" * 60)
    demo_simplify(
        "x | 0",
        "恒等式: x|0 = x"
    )

    print("-" * 60)
    print("Example 6: AND with zero (absorb)")
    print("-" * 60)
    demo_simplify(
        "x & 0",
        "吸收律: x&0 = 0"
    )

    print("-" * 60)
    print("Example 7: No obfuscation detected")
    print("-" * 60)
    demo_simplify(
        "x + y",
        "普通表达式不会被误简化"
    )

    banner("Z3 Equivalence Proof Details")

    proofs = [
        ("(x | y) - (x & y)", "x ^ y", True),
        ("(x | y) - (x & y)", "x + y", False),
        ("(x & ~y) | (~x & y)", "x ^ y", True),
        ("(x | y) + (x & y)", "x + y", True),
        ("(x | y) + (x & y)", "x - y", False),
    ]

    print(f"  {'Pattern':<30} {'Candidate':<15} {'Equivalent?':<12} {'Z3 Result'}")
    print(f"  {'-'*30} {'-'*15} {'-'*12} {'-'*10}")
    for pattern, candidate, expected in proofs:
        result = verify_equivalence(pattern, candidate, bit_width=32)
        mark = "✅" if result == expected else "❌"
        eq_str = "YES" if result else "NO"
        print(f"  {pattern:<30} {candidate:<15} {eq_str:<12} {mark}")

    print()


if __name__ == "__main__":
    main()
