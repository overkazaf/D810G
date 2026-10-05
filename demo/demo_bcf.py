#!/usr/bin/env python3
"""D810G Bogus Control Flow Demo — detect and strip fake branches."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.bcf.detector import detect_and_remove_bcf


def banner(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def main():
    banner("D810G Demo: Bogus Control Flow (BCF) Detection & Removal")

    print("OLLVM's BCF transform inserts fake conditional branches guarded")
    print("by opaque predicates. The fake branch is never taken, but it")
    print("confuses static analysis tools and reverse engineers.\n")

    print("-" * 70)
    print("Example: Function with 3 BCF-inserted fake branches")
    print("-" * 70)

    print("""
  Original:                After BCF:

    +---+                  +--------------+
    | A |                  | if(x == x)   | <- always true
    +-+-+                  +--+----+------+
      |                       |    |
    +-v-+                +----v+  +v--------+
    | B |                |  A  |  | bogus #1 | <- junk code
    +-+-+                |(real)|  |(dead)    |
      |                  +--+--+  +--+-------+
    +-v-+                   |        |
    | C |                   +--------+
    +-+-+                   |
      |                  +--v--------------+
    +-v-+                | if((x&1)==2)    | <- always false
    |ret|                +--+----+--------+
    +---+                   |    |
                        +---v+  +v----------+
                        | C  |  | bogus #2  |
                        |(real)|  |(dead)    |
                        +--+-+  +--+--------+
                           |       |
                           +-------+
                           |
                        +--v---------------+
                        | if((x^x)!=0)     | <- always false
                        +--+----+----------+
                           |    |
                       +---v+  +v----------+
                       |ret |  | bogus #3  |
                       |(real)|  |(dead)    |
                       +----+  +-----------+
    """)

    blocks = [
        # BCF #1: x == x (always true) -> real=0x1100, bogus=0x1200
        {"addr": 0x1000, "condition": "x == x", "succs": [0x1100, 0x1200], "size": 24},
        {"addr": 0x1100, "succs": [0x1300], "size": 32},
        {"addr": 0x1200, "succs": [0x1300], "size": 48},
        # BCF #2: (x & 1) == 2 (always false) -> real=0x1500, bogus=0x1400
        {"addr": 0x1300, "condition": "(x & 1) == 2", "succs": [0x1400, 0x1500], "size": 20},
        {"addr": 0x1400, "succs": [0x1600], "size": 36},
        {"addr": 0x1500, "succs": [0x1600], "size": 28},
        # BCF #3: (x ^ x) != 0 (always false) -> real=0x1800, bogus=0x1700
        {"addr": 0x1600, "condition": "(x ^ x) != 0", "succs": [0x1700, 0x1800], "size": 20},
        {"addr": 0x1700, "succs": [0x1900], "size": 40},
        {"addr": 0x1800, "succs": [0x1900], "size": 16},
        {"addr": 0x1900, "succs": [], "size": 8},
    ]

    result = detect_and_remove_bcf({"blocks": blocks})

    print(f"  D810G Analysis:")
    print(f"    Status: {result['status']}")
    print(f"    BCF patterns found: {len(result['candidates'])}")
    print()

    for i, c in enumerate(result["candidates"], 1):
        label = "[ALWAYS TRUE] " if c["classification"] == "always_true" else "[ALWAYS FALSE]"
        print(f"    BCF #{i}: {label}")
        print(f"      Branch at:      0x{c['branch_addr']:04x}")
        print(f"      Condition:      {c['condition']}")
        print(f"      Classification: {c['classification']}")
        print(f"      Real target:    0x{c['real_target']:04x}")
        print(f"      Bogus target:   0x{c['bogus_target']:04x}")
        print()

    print(f"    Patches generated: {len(result['patches'])}")
    for p in result["patches"]:
        print(f"      0x{p['address']:04x}: {p['action']} -> 0x{p['target']:04x}")

    bogus_addrs = {c["bogus_target"] for c in result["candidates"]}
    bogus_bytes = sum(b["size"] for b in blocks if b["addr"] in bogus_addrs)
    total_bytes = sum(b["size"] for b in blocks)
    print(f"\n    Dead code identified: {bogus_bytes} bytes ({bogus_bytes*100//total_bytes}% of function)")
    print(f"    -> After BCF removal + DCE, function shrinks from {total_bytes} to {total_bytes - bogus_bytes} bytes")
    print()


if __name__ == "__main__":
    main()
