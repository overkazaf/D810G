#!/usr/bin/env python3
"""D810G Control Flow Deflattening Demo — synthetic OLLVM example."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.deflattener.detector import detect_cff_pattern
from d810g_engine.deflattener.ollvm import deflat_ollvm


def banner(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main():
    banner("D810G Demo: Control Flow Deflattening")

    print("OLLVM's Control Flow Flattening (CFF) transforms a function's")
    print("natural control flow into a state machine with a central dispatcher.")
    print()

    # ── Simulate an OLLVM-flattened function ──
    print("-" * 60)
    print("Original control flow (before obfuscation)")
    print("-" * 60)
    print("""
    ┌─────────┐
    │  entry  │
    └────┬────┘
         │
    ┌────▼────┐
    │ if(x>0) │
    └──┬───┬──┘
       │   │
  ┌────▼┐ ┌▼────┐
  │ r=  │ │ r=  │
  │ x+y │ │ x-y │
  └──┬──┘ └──┬──┘
     │       │
    ┌▼───────▼┐
    │ return r│
    └─────────┘
    """)

    print("-" * 60)
    print("After OLLVM CFF (state machine)")
    print("-" * 60)
    print("""
    ┌───────────┐
    │   entry   │
    │ state=0xAA│
    └─────┬─────┘
          │
    ┌─────▼──────┐◄──────────────────────┐
    │ dispatcher  │                       │
    │ switch(state)│                      │
    └┬──┬──┬──┬──┘                       │
     │  │  │  │                          │
   ┌─▼┐┌▼─┐┌─▼┐┌──▼──┐                  │
   │AA││BB││CC││ ret  │                  │
   │  ││  ││  │└─────┘                  │
   │s=││s=││s=│                          │
   │BB││CC││DD│                          │
   └─┬┘└┬─┘└─┬┘                         │
     │  │    │                           │
     └──┴────┴───────────────────────────┘

    Each original basic block becomes a "case" that updates
    the state variable and jumps back to the dispatcher.
    """)

    print("-" * 60)
    print("D810G Detection")
    print("-" * 60)

    # Synthetic block graph representing the OLLVM-flattened function
    blocks = [
        {
            "addr": 0x401000,
            "type": "dispatcher",
            "succs": [0x401100, 0x401200, 0x401300, 0x401400, 0x401500],
            "desc": "switch(state) — central dispatcher"
        },
        {
            "addr": 0x401100,
            "type": "case",
            "state_update": 0xAABBCCDD,
            "succs": [0x401000],
            "desc": "case 0xAA: entry block, sets state=0xBB"
        },
        {
            "addr": 0x401200,
            "type": "case",
            "state_update": 0x11223344,
            "succs": [0x401000],
            "desc": "case 0xBB: if(x>0), sets state=0xCC or 0xDD"
        },
        {
            "addr": 0x401300,
            "type": "case",
            "state_update": 0x55667788,
            "succs": [0x401000],
            "desc": "case 0xCC: r=x+y, sets state=0xEE"
        },
        {
            "addr": 0x401400,
            "type": "case",
            "state_update": 0x99AABBCC,
            "succs": [0x401000],
            "desc": "case 0xDD: r=x-y, sets state=0xEE"
        },
        {
            "addr": 0x401500,
            "type": "return",
            "succs": [],
            "desc": "case 0xEE: return r"
        },
    ]

    print("\n  Basic block graph analysis:")
    for b in blocks:
        succs_str = ", ".join(f"0x{s:06x}" for s in b["succs"]) or "none"
        state = f"state=0x{b['state_update']:08X}" if "state_update" in b else ""
        print(f"    0x{b['addr']:06x} [{b['type']:>10}] → [{succs_str}] {state}")
        print(f"    {'':>26}  {b['desc']}")

    # Run detection
    pattern = detect_cff_pattern(blocks)

    print(f"\n  Detection result:")
    if pattern:
        print(f"    ✅ CFF pattern detected!")
        print(f"    Type:          {pattern['type']}")
        print(f"    Dispatcher:    0x{pattern['dispatcher']:06x}")
        print(f"    Case blocks:   {len(pattern['case_blocks'])} blocks")
        print(f"    Total cases:   {pattern['num_cases']}")
        for addr in pattern["case_blocks"]:
            print(f"      → 0x{addr:06x}")
    else:
        print(f"    ❌ No CFF pattern found")

    print()

    print("-" * 60)
    print("Full Pipeline (detect → solve → patch)")
    print("-" * 60)

    result = deflat_ollvm({
        "blocks": [b for b in blocks],  # use same blocks
        "binary_hex": "90" * 512,  # placeholder bytes
        "arch": "x86_64",
        "state_var_offset": 0x10,
        "state_var_size": 4,
    })

    print(f"\n  Pipeline result:")
    print(f"    Status:       {result['status']}")
    print(f"    Pattern:      {result['pattern']['type']}")
    print(f"    Transitions:  {len(result['transitions'])} recovered")
    print(f"    Patches:      {len(result['patches'])} generated")
    print()
    print("  Note: symbolic.py uses stub implementation.")
    print("  Full unicorn/angr integration will generate actual")
    print("  binary patches to restore the original control flow.")
    print()

    # ── Normal code (negative test) ──
    print("-" * 60)
    print("Negative test: normal (non-obfuscated) function")
    print("-" * 60)

    normal_blocks = [
        {"addr": 0x401000, "succs": [0x401010]},
        {"addr": 0x401010, "succs": [0x401020, 0x401030]},
        {"addr": 0x401020, "succs": [0x401040]},
        {"addr": 0x401030, "succs": [0x401040]},
        {"addr": 0x401040, "succs": []},
    ]

    normal_pattern = detect_cff_pattern(normal_blocks)
    print(f"\n  Normal function with if/else:")
    print(f"    entry → branch → [true_path | false_path] → return")
    print(f"    Detection: {'❌ No CFF (correct!)' if normal_pattern is None else '⚠️ False positive!'}")
    print()


if __name__ == "__main__":
    main()
