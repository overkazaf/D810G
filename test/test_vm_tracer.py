import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.virtualization.tracer import (
    VMInstruction, VMTrace, trace_bytecode, trace_vm,
)


SAMPLE_HANDLERS = [
    {"opcode": 0x01, "semantics": "mov", "operand_count": 2, "address": 0x1100},
    {"opcode": 0x02, "semantics": "add", "operand_count": 3, "address": 0x1200},
    {"opcode": 0x03, "semantics": "load_imm", "operand_count": 2, "address": 0x1300},
    {"opcode": 0x04, "semantics": "ret", "operand_count": 1, "address": 0x1400},
    {"opcode": 0x05, "semantics": "sub", "operand_count": 3, "address": 0x1500},
    {"opcode": 0x06, "semantics": "cmp", "operand_count": 2, "address": 0x1600},
    {"opcode": 0x07, "semantics": "branch", "operand_count": 1, "address": 0x1700},
]


class TestVMInstruction:

    def test_to_dict(self):
        insn = VMInstruction(pc=0, opcode=1, operands=[0, 1],
                            handler_addr=0x1100, semantics="mov")
        d = insn.to_dict()
        assert d["opcode"] == 1
        assert d["semantics"] == "mov"
        assert d["operands"] == [0, 1]

    def test_repr(self):
        insn = VMInstruction(pc=0, opcode=2, operands=[0, 1, 2],
                            handler_addr=0x1200, semantics="add")
        r = repr(insn)
        assert "add" in r


class TestVMTrace:

    def test_add_instruction(self):
        trace = VMTrace()
        insn = VMInstruction(0, 1, [0, 1], 0x1100, "mov")
        trace.add_instruction(insn)
        assert len(trace.instructions) == 1
        assert trace.handler_hits[0x1100] == 1

    def test_to_dict(self):
        trace = VMTrace()
        trace.add_instruction(VMInstruction(0, 1, [0, 1], 0x1100, "mov"))
        trace.add_instruction(VMInstruction(3, 4, [0], 0x1400, "ret"))
        d = trace.to_dict()
        assert d["instruction_count"] == 2
        assert d["unique_handlers"] == 2


class TestBytecodeTracing:

    def test_simple_program(self):
        """Trace: load_imm r0, 42; load_imm r1, 10; add r2, r0, r1; ret r2"""
        bytecode = bytes([
            0x03, 0x00, 42,     # load_imm r0, 42
            0x03, 0x01, 10,     # load_imm r1, 10
            0x02, 0x02, 0x00, 0x01,  # add r2, r0, r1
            0x04, 0x02,         # ret r2
        ])
        trace = trace_bytecode(bytecode, SAMPLE_HANDLERS)
        assert len(trace.instructions) == 4
        assert trace.instructions[0].semantics == "load_imm"
        assert trace.instructions[1].semantics == "load_imm"
        assert trace.instructions[2].semantics == "add"
        assert trace.instructions[3].semantics == "ret"

    def test_stops_at_ret(self):
        """Tracing stops when ret handler is encountered."""
        bytecode = bytes([
            0x03, 0x00, 1,   # load_imm
            0x04, 0x00,      # ret
            0x03, 0x01, 2,   # load_imm (should not be reached)
        ])
        trace = trace_bytecode(bytecode, SAMPLE_HANDLERS)
        assert len(trace.instructions) == 2

    def test_unknown_opcode(self):
        """Unknown opcodes are recorded and skipped."""
        bytecode = bytes([
            0xFF,            # unknown
            0x04, 0x00,      # ret
        ])
        trace = trace_bytecode(bytecode, SAMPLE_HANDLERS)
        assert trace.instructions[0].semantics == "unknown"
        assert trace.instructions[1].semantics == "ret"

    def test_max_instructions_limit(self):
        """Tracing respects max_instructions."""
        bytecode = bytes([0x03, 0x00, 1] * 100)  # 100 load_imm
        trace = trace_bytecode(bytecode, SAMPLE_HANDLERS, max_instructions=5)
        assert len(trace.instructions) == 5

    def test_empty_bytecode(self):
        trace = trace_bytecode(b"", SAMPLE_HANDLERS)
        assert len(trace.instructions) == 0


class TestPseudocode:

    def test_arithmetic_program(self):
        """Generate pseudocode for: r0=42, r1=10, r2=r0+r1, return r2"""
        bytecode = bytes([
            0x03, 0x00, 42,
            0x03, 0x01, 10,
            0x02, 0x02, 0x00, 0x01,
            0x04, 0x02,
        ])
        trace = trace_bytecode(bytecode, SAMPLE_HANDLERS)
        pseudo = trace.to_pseudocode()
        assert "r0 = 42" in pseudo
        assert "r1 = 10" in pseudo
        assert "r2 = r0 + r1" in pseudo
        assert "return r2" in pseudo

    def test_branch_pseudocode(self):
        bytecode = bytes([
            0x06, 0x00, 0x01,   # cmp r0, r1
            0x07, 0x10,         # branch to vm_pc 0x10
            0x04, 0x00,         # ret r0
        ])
        trace = trace_bytecode(bytecode, SAMPLE_HANDLERS)
        pseudo = trace.to_pseudocode()
        assert "cmp" in pseudo
        assert "goto" in pseudo or "if" in pseudo


class TestTraceVMEntry:

    def test_trace_vm_api(self):
        result = trace_vm({
            "bytecode_hex": "03" + "00" + "2a" + "03" + "01" + "0a" + "02" + "02" + "00" + "01" + "04" + "02",
            "handlers": SAMPLE_HANDLERS,
        })
        assert result["status"] == "traced"
        assert result["trace"]["instruction_count"] == 4
        assert "r0 = 42" in result["pseudocode"]
        assert "return r2" in result["pseudocode"]

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.virtualization import register_handlers
        server = Server()
        register_handlers(server)
        assert "vm.trace" in server._handlers
