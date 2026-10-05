#!/usr/bin/env python3
"""D810G VM Devirtualization Demo — detect VM, trace bytecode, recover pseudocode."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.virtualization.analyzer import analyze_vm, detect_vm_dispatcher
from d810g_engine.virtualization.tracer import trace_vm, trace_bytecode


def banner(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def main():
    banner("D810G Demo: VM Devirtualization")

    print("Tigress's virtualization transform converts native code into a")
    print("custom bytecode VM. D810G detects the VM, classifies handlers,")
    print("traces bytecode execution, and generates pseudocode.\n")

    print("-" * 70)
    print("Step 1: VM Dispatcher Detection")
    print("-" * 70)

    # Simulate a VM-protected function with dispatcher + handler blocks.
    # The dispatcher has high in-degree and high out-degree (many handlers
    # jump back to it, and it dispatches to all of them).
    vm_blocks = [
        # Dispatcher: fetches opcode, dispatches to handler
        {"addr": 0x401000, "succs": [0x401100, 0x401200, 0x401300, 0x401400, 0x401500, 0x401600]},
        # Handler: load_imm (load immediate to register)
        {"addr": 0x401100, "succs": [0x401000], "insn_count": 4, "has_memory_access": True, "has_arithmetic": False},
        # Handler: mov (register to register)
        {"addr": 0x401200, "succs": [0x401000], "insn_count": 3, "has_memory_access": False, "has_arithmetic": False},
        # Handler: add (arithmetic)
        {"addr": 0x401300, "succs": [0x401000], "insn_count": 3, "has_memory_access": False, "has_arithmetic": True},
        # Handler: sub (arithmetic)
        {"addr": 0x401400, "succs": [0x401000], "insn_count": 3, "has_memory_access": False, "has_arithmetic": True},
        # Handler: cmp + branch
        {"addr": 0x401500, "succs": [0x401000, 0x401600], "insn_count": 5},
        # Handler: ret
        {"addr": 0x401600, "succs": [], "insn_count": 2},
    ]

    result = analyze_vm({
        "blocks": vm_blocks,
        "binary_hex": "90" * 200,
    })

    print(f"\n  Status: {result['status']}")
    if result.get("dispatcher"):
        print(f"  Dispatcher: 0x{result['dispatcher']['dispatcher_addr']:x}")
    if result.get("context"):
        print(f"  Handlers detected: {result['context']['handler_count']}")
        print()

        print("  Handler Table:")
        print(f"  {'Opcode':<10} {'Address':<14} {'Semantics':<12}")
        print(f"  {'-'*10} {'-'*14} {'-'*12}")
        for h in result["context"]["handlers"]:
            print(f"  {h['opcode_hex']:<10} 0x{h['address']:x}{'':<6} {h['semantics']:<12}")
        print()
    else:
        print("  (No VM context detected)")
        print()

    print("-" * 70)
    print("Step 2: Bytecode Tracing")
    print("-" * 70)

    # Define the handler descriptors for tracing.
    # These represent a simple instruction set for a toy VM.
    handlers = [
        {"opcode": 0x01, "semantics": "load_imm", "operand_count": 2, "address": 0x401100},
        {"opcode": 0x02, "semantics": "mov",      "operand_count": 2, "address": 0x401200},
        {"opcode": 0x03, "semantics": "add",      "operand_count": 3, "address": 0x401300},
        {"opcode": 0x04, "semantics": "sub",      "operand_count": 3, "address": 0x401400},
        {"opcode": 0x05, "semantics": "cmp",      "operand_count": 2, "address": 0x401500},
        {"opcode": 0x06, "semantics": "ret",      "operand_count": 1, "address": 0x401600},
    ]

    # Bytecode for: add(42, 17) -> result = 59
    # load_imm r0, 42
    # load_imm r1, 17
    # add r2, r0, r1
    # ret r2
    bytecode = bytes([
        0x01, 0x00, 42,          # load_imm r0, 42
        0x01, 0x01, 17,          # load_imm r1, 17
        0x03, 0x02, 0x00, 0x01,  # add r2, r0, r1
        0x06, 0x02,              # ret r2
    ])

    print(f"\n  Bytecode ({len(bytecode)} bytes):")
    print(f"    {bytecode.hex()}")
    print()

    trace_result = trace_vm({
        "bytecode_hex": bytecode.hex(),
        "handlers": handlers,
    })

    print(f"  Traced {trace_result['trace']['instruction_count']} VM instructions")
    print(f"  Unique handlers used: {trace_result['trace']['unique_handlers']}")
    print()

    print("  Instruction trace:")
    for insn in trace_result["trace"]["instructions"]:
        ops = ", ".join(str(o) for o in insn["operands"])
        print(f"    PC={insn['pc']:04x}  {insn['semantics']:>10}({ops})")
    print()

    print("-" * 70)
    print("Step 3: Recovered Pseudocode")
    print("-" * 70)

    print(f"\n{trace_result['pseudocode']}")
    print()

    banner("More Complex Example: Fibonacci")

    # Bytecode for a linear fibonacci-like computation:
    # r0 = n (input), r1 = 0 (a), r2 = 1 (b), r3 = temp
    # r3 = r1 + r2; r1 = r2; r2 = r3; r0 -= 1; ret r1
    fib_bytecode = bytes([
        0x01, 0x00, 10,          # load_imm r0, 10 (n=10)
        0x01, 0x01, 0,           # load_imm r1, 0  (a=0)
        0x01, 0x02, 1,           # load_imm r2, 1  (b=1)
        # One iteration of the loop body (unrolled):
        0x03, 0x03, 0x01, 0x02,  # add r3, r1, r2  (temp = a + b)
        0x02, 0x01, 0x02,        # mov r1, r2      (a = b)
        0x02, 0x02, 0x03,        # mov r2, r3      (b = temp)
        0x01, 0x04, 1,           # load_imm r4, 1
        0x04, 0x00, 0x00, 0x04,  # sub r0, r0, r4  (n -= 1)
        0x06, 0x01,              # ret r1
    ])

    fib_result = trace_vm({
        "bytecode_hex": fib_bytecode.hex(),
        "handlers": handlers,
    })

    print(f"  Fibonacci VM program ({len(fib_bytecode)} bytes):")
    print(f"  Traced {fib_result['trace']['instruction_count']} instructions\n")
    print("  Pseudocode:")
    for line in fib_result["pseudocode"].split("\n"):
        print(f"    {line}")
    print()


if __name__ == "__main__":
    main()
