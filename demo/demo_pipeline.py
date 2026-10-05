#!/usr/bin/env python3
"""D810G Full Pipeline Demo — all 6 deobfuscation passes in action."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.pipeline.orchestrator import run_pipeline


def banner(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def main():
    banner("D810G Demo: Full Deobfuscation Pipeline")

    print("The pipeline chains 6 passes in optimal order, iterating until")
    print("no more changes are made (fixpoint).\n")
    print("  Pass order: deflat_ollvm -> deflat_tigress -> bcf -> opaque -> dce -> strings\n")

    print("-" * 70)
    print("Scenario: OLLVM-obfuscated function with BCF + opaque predicates")
    print("-" * 70)

    # Synthetic function with multiple obfuscation layers:
    # - BCF: fake branches guarded by opaque predicates
    # - Opaque predicates: always-true/false conditions
    # - Dead code: unreachable bogus blocks
    blocks = [
        # Entry block with BCF (opaque predicate x==x guards a fake branch)
        {
            "addr": 0x401000,
            "condition": "x == x",
            "succs": [0x401100, 0x401200],
            "size": 24,
        },
        # Real block (x==x is always true, so this is the real path)
        {
            "addr": 0x401100,
            "succs": [0x401300],
            "size": 32,
        },
        # Bogus block (dead code after BCF removal)
        {
            "addr": 0x401200,
            "succs": [0x401300],
            "size": 48,
        },
        # Second BCF layer
        {
            "addr": 0x401300,
            "condition": "(x & 1) == 2",
            "succs": [0x401400, 0x401500],
            "size": 20,
        },
        # Bogus block (always-false, so true branch is bogus)
        {
            "addr": 0x401400,
            "succs": [0x401600],
            "size": 36,
        },
        # Real block
        {
            "addr": 0x401500,
            "succs": [0x401600],
            "size": 28,
        },
        # Return
        {
            "addr": 0x401600,
            "succs": [],
            "size": 8,
        },
    ]

    print("\n  Input function: 7 blocks, 196 bytes total")
    print("  Obfuscation layers:")
    print("    - BCF at 0x401000: condition 'x == x' (always true)")
    print("    - BCF at 0x401300: condition '(x & 1) == 2' (always false)")
    print("    - 2 bogus blocks (0x401200, 0x401400)")
    print()

    result = run_pipeline({
        "blocks": blocks,
        "binary_hex": "90" * 500,
        "entry_addr": 0x401000,
        "arch": "x86_64",
    })

    print(f"  Pipeline result: {result['status']}")
    print(f"  Iterations: {result['iterations']}")
    print(f"  Fixpoint: {result['fixpoint']}")
    print(f"  Total patches: {result['total_patches']}")
    print(f"  Time: {result['total_time_ms']:.0f}ms")
    print()

    print("  Pass details:")
    for p in result.get("passes", []):
        icon = "[+]" if p["patches"] > 0 else "[ ]"
        print(f"    {icon} [{p['name']:>16}] {p['status']:<30} {p['patches']} patches ({p['time_ms']:.0f}ms)")

    print(f"\n  Summary: {result.get('summary', '')}")

    banner("Scenario: Clean function (no obfuscation)")

    clean_blocks = [
        {"addr": 0x401000, "succs": [0x401010, 0x401020], "size": 16},
        {"addr": 0x401010, "succs": [0x401030], "size": 12},
        {"addr": 0x401020, "succs": [0x401030], "size": 12},
        {"addr": 0x401030, "succs": [], "size": 4},
    ]

    result2 = run_pipeline({
        "blocks": clean_blocks,
        "binary_hex": "90" * 100,
        "entry_addr": 0x401000,
    })

    print(f"  Result: {result2['status']}")
    print(f"  Total patches: {result2['total_patches']} (no obfuscation found)")
    print(f"  Fixpoint: {result2['fixpoint']} (converged immediately)")
    print()


if __name__ == "__main__":
    main()
