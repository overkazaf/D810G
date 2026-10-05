#!/usr/bin/env python3
"""D810G Opaque Predicate Elimination Demo — concrete examples."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.opaque.predicate import classify_predicate
from d810g_engine.opaque import eliminate_predicates


def banner(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def demo_classify(expr, bit_width=32, signed=True, desc=""):
    result = classify_predicate(expr, bit_width=bit_width, signed=signed)
    icons = {
        "always_true": "🟢 ALWAYS TRUE  → dead false-branch, can be NOPed",
        "always_false": "🔴 ALWAYS FALSE → dead true-branch, can be NOPed",
        "dynamic": "⚪ DYNAMIC      → real condition, keep as-is",
    }
    if desc:
        print(f"  # {desc}")
    print(f"  Predicate:      {expr}")
    print(f"  Classification: {icons[result['classification']]}")
    print(f"  Variables:      {result['variables']}")
    print()


def main():
    banner("D810G Demo: Opaque Predicate Elimination")

    print("Obfuscators insert 'opaque predicates' — conditions that LOOK")
    print("data-dependent but always evaluate the same way. They add fake")
    print("branches to confuse disassemblers and analysts.")
    print("D810G uses Z3 SMT solver to prove them constant.\n")

    print("-" * 60)
    print("Classic opaque predicates (always true)")
    print("-" * 60)

    demo_classify(
        "x == x",
        desc="Identity: any value equals itself"
    )

    demo_classify(
        "(x * x) >= 0",
        signed=False,
        desc="Unsigned square is always non-negative"
    )

    demo_classify(
        "(x | 1) != 0",
        desc="OR with 1 is never zero"
    )

    print("-" * 60)
    print("Classic opaque predicates (always false)")
    print("-" * 60)

    demo_classify(
        "(x & 1) == 2",
        desc="x&1 can only be 0 or 1, never 2"
    )

    demo_classify(
        "(x & 3) == 4",
        desc="x&3 can only be 0-3, never 4"
    )

    demo_classify(
        "(x ^ x) != 0",
        desc="x^x is always 0, so != 0 is always false"
    )

    print("-" * 60)
    print("Real conditions (dynamic — not opaque)")
    print("-" * 60)

    demo_classify(
        "x > 5",
        desc="Depends on x — this is a real branch"
    )

    demo_classify(
        "(x & 0xff) == 0x41",
        desc="Checks if low byte is 'A' — legitimate condition"
    )

    banner("Batch Elimination API")

    print("In practice, D810G scans all conditional branches in a function")
    print("and batch-classifies them:\n")

    result = eliminate_predicates({
        "predicates": [
            {"expression": "x == x",        "address": 0x401000, "bit_width": 32},
            {"expression": "(x & 1) == 2",  "address": 0x401020, "bit_width": 32},
            {"expression": "x > 5",         "address": 0x401040, "bit_width": 32},
            {"expression": "(x | 1) != 0",  "address": 0x401060, "bit_width": 32},
            {"expression": "(x ^ x) != 0",  "address": 0x401080, "bit_width": 32},
        ]
    })

    print(f"  Scanned {len(result['results'])} predicates:")
    for r in result["results"]:
        icon = {"always_true": "🟢", "always_false": "🔴", "dynamic": "⚪"}[r["classification"]]
        print(f"    {icon} 0x{r['address']:08x}: {r['expression']:<25} → {r['classification']}")

    print(f"\n  Generated {len(result['patches'])} patches:")
    for p in result["patches"]:
        print(f"    0x{p['address']:08x}: {p['action']}")

    print(f"\n  → {len(result['patches'])} opaque predicates eliminated, "
          f"{len(result['results']) - len(result['patches'])} real conditions preserved\n")


if __name__ == "__main__":
    main()
