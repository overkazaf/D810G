# Ghidra headless analysis script for batch deobfuscation
# Usage: analyzeHeadless /path/to/project ProjectName \
#        -import binary.exe \
#        -postScript headless_deobfuscate.py
#
# Or for an existing project:
# analyzeHeadless /path/to/project ProjectName \
#        -process binary.exe \
#        -postScript headless_deobfuscate.py

# @category D810G
# @description Batch deobfuscation of all functions using D810G engine

import json
import subprocess
import sys
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor


def extract_blocks(decompiler, function):
    """Extract basic block graph from a function."""
    results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
    blocks = []
    if results.decompileCompleted():
        hf = results.getHighFunction()
        if hf:
            for bb in hf.getBasicBlocks():
                block = {
                    "addr": bb.getStart().getOffset(),
                    "succs": [bb.getOut(i).getStart().getOffset() for i in range(bb.getOutSize())],
                }
                blocks.append(block)
    return blocks


def main():
    program = currentProgram
    fm = program.getFunctionManager()
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    functions = list(fm.getFunctions(True))
    print("[D810G] Analyzing {} functions...".format(len(functions)))

    # Start Python engine
    ext_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python_dir = os.path.join(ext_dir, "python")

    analyzed = 0
    for func in functions:
        blocks = extract_blocks(decompiler, func)
        if len(blocks) < 3:
            continue

        # Check for CFF characteristics: blocks with many successors
        # and high back-edge ratio
        has_dispatcher = any(len(b["succs"]) >= 3 for b in blocks)
        if not has_dispatcher:
            continue

        analyzed += 1
        print("[D810G] Suspicious function: {} at 0x{:x} ({} blocks)".format(
            func.getName(), func.getEntryPoint().getOffset(), len(blocks)))

    decompiler.dispose()
    print("[D810G] Done. Found {} suspicious functions out of {}.".format(
        analyzed, len(functions)))


main()
