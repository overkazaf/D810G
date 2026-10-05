#!/usr/bin/env python3
"""D810G Master Demo — run all demonstration scripts."""

import subprocess
import sys
import os
from pathlib import Path


def run_demo(name, script):
    print(f"\n{'#'*70}")
    print(f"# Running: {name}")
    print(f"{'#'*70}")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(script.parent.parent / "python")

    result = subprocess.run(
        [sys.executable, str(script)],
        env=env,
        capture_output=False,
    )
    return result.returncode


def main():
    demo_dir = Path(__file__).parent

    demos = [
        ("MBA Expression Simplification", demo_dir / "demo_mba.py"),
        ("Multi-Pass Deep MBA", demo_dir / "demo_deep_mba.py"),
        ("Opaque Predicate Elimination", demo_dir / "demo_opaque.py"),
        ("Bogus Control Flow Removal", demo_dir / "demo_bcf.py"),
        ("Control Flow Deflattening", demo_dir / "demo_deflat.py"),
        ("String Decryption", demo_dir / "demo_strings.py"),
        ("VM Devirtualization", demo_dir / "demo_vm.py"),
        ("Full Pipeline", demo_dir / "demo_pipeline.py"),
    ]

    print("=" * 70)
    print("  D810G -- Complete Demo Suite")
    print("  Demonstrating all deobfuscation capabilities")
    print("=" * 70)

    passed = 0
    failed = 0

    for name, script in demos:
        if not script.exists():
            print(f"\n  [SKIP] {name}: {script.name} not found")
            continue

        rc = run_demo(name, script)
        if rc == 0:
            passed += 1
        else:
            failed += 1
            print(f"\n  [FAIL] {name} failed (exit code {rc})")

    print(f"\n{'='*70}")
    print(f"  Demo Summary: {passed} passed, {failed} failed")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
