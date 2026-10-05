#!/usr/bin/env python3
"""D810G Deep MBA Simplification Demo — multi-pass iterative simplification."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.mba import simplify_expression_deep


def banner(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def demo_deep(expr, desc=""):
    result = simplify_expression_deep({
        "expression": expr,
        "verify": True,
        "max_iterations": 10,
    })
    if desc:
        print(f"  # {desc}")
    print(f"  Input:      {expr}")

    for step in result.get("chain", []):
        print(f"  Step {step['step']:>2}:    {step['after']}")
        print(f"             rule: {step['rule_id']}")

    if result["iterations"] == 0:
        print(f"  Result:    {result['simplified']} (no simplification needed)")
    else:
        verified = "[Z3 verified]" if result["verified"] else "[unverified]"
        print(f"  Final:     {result['simplified']}  {verified}")
        print(f"  Iterations: {result['iterations']}, fixpoint: {result['fixpoint']}")
    print()


def main():
    banner("D810G Demo: Multi-Pass Deep MBA Simplification")

    print("Real obfuscated code has NESTED MBA expressions -- simplifying one")
    print("layer reveals another. D810G iterates until no more rules apply.\n")

    print("-" * 70)
    print("Example 1: Nested XOR -- two layers")
    print("-" * 70)
    demo_deep(
        "((x | y) - (x & y)) ^ ((x | y) - (x & y))",
        "(x^y) ^ (x^y) = 0  (self-XOR after inner simplification)"
    )

    print("-" * 70)
    print("Example 2: Chained identity -- OR with zero")
    print("-" * 70)
    demo_deep(
        "(x | 0) | 0",
        "x|0 = x, then x|0 = x again"
    )

    print("-" * 70)
    print("Example 3: Sub-expression simplification")
    print("-" * 70)
    demo_deep(
        "a + ((x | y) - (x & y))",
        "Inner (x|y)-(x&y) becomes x^y"
    )

    print("-" * 70)
    print("Example 4: No simplification needed")
    print("-" * 70)
    demo_deep(
        "a + b * c",
        "Normal arithmetic -- no MBA patterns"
    )

    print("-" * 70)
    print("Example 5: De Morgan's law")
    print("-" * 70)
    demo_deep(
        "~(~x & ~y)",
        "De Morgan: ~(~x & ~y) = x | y"
    )

    print("-" * 70)
    print("Example 6: Complex nested -- AND via OR-XOR")
    print("-" * 70)
    demo_deep(
        "(x | y) - ((x & ~y) | (~x & y))",
        "(x|y) - (x^y) = x & y"
    )

    banner("Batch Simplification Statistics")

    test_exprs = [
        "(x | y) - (x & y)",
        "(x & ~y) | (~x & y)",
        "(x | y) + (x & y)",
        "x ^ x",
        "x | 0",
        "x & 0",
        "x + y",
        "~(~x & ~y)",
        "((x | y) - (x & y)) ^ ((x | y) - (x & y))",
        "(x | 0) | 0",
    ]

    simplified_count = 0
    total_steps = 0

    print(f"  {'Expression':<50} {'Result':<15} {'Steps'}")
    print(f"  {'-'*50} {'-'*15} {'-'*5}")
    for expr in test_exprs:
        result = simplify_expression_deep({"expression": expr, "verify": False})
        steps = result["iterations"]
        total_steps += steps
        was_simplified = result["simplified"] != expr
        if was_simplified:
            simplified_count += 1
        mark = "[+]" if was_simplified else "[ ]"
        print(f"  {mark} {expr:<48} {result['simplified']:<15} {steps}")

    print(f"\n  {simplified_count}/{len(test_exprs)} expressions simplified, {total_steps} total steps")
    print()


if __name__ == "__main__":
    main()
