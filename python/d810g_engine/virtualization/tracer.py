"""Trace VM bytecode execution to recover original instruction sequence."""

from __future__ import annotations
from typing import Any


class VMInstruction:
    """A recovered VM instruction from bytecode tracing."""

    def __init__(self, pc: int, opcode: int, operands: list[int],
                 handler_addr: int, semantics: str) -> None:
        """Initialize a traced VM instruction."""
        self.pc = pc
        self.opcode = opcode
        self.operands = operands
        self.handler_addr = handler_addr
        self.semantics = semantics

    def to_dict(self) -> dict[str, Any]:
        """Serialize the instruction to a JSON-compatible dict."""
        return {
            "pc": self.pc,
            "opcode": self.opcode,
            "opcode_hex": f"0x{self.opcode:02x}",
            "operands": self.operands,
            "handler_addr": self.handler_addr,
            "handler_hex": f"0x{self.handler_addr:x}",
            "semantics": self.semantics,
        }

    def __repr__(self):
        ops = ", ".join(str(o) for o in self.operands)
        return f"VM[{self.pc:04x}]: {self.semantics}({ops})"


class VMTrace:
    """A complete execution trace of a VM-protected function."""

    def __init__(self) -> None:
        """Initialize an empty trace."""
        self.instructions: list[VMInstruction] = []
        self.handler_hits: dict[int, int] = {}  # handler_addr -> hit count
        self.bytecode: bytes = b""
        self.register_states: list[dict[str, int]] = []

    def add_instruction(self, insn: VMInstruction) -> None:
        """Append an instruction and update handler hit counts."""
        self.instructions.append(insn)
        self.handler_hits[insn.handler_addr] = self.handler_hits.get(insn.handler_addr, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize the trace to a JSON-compatible dict."""
        return {
            "instruction_count": len(self.instructions),
            "unique_handlers": len(self.handler_hits),
            "instructions": [i.to_dict() for i in self.instructions],
            "handler_hits": {
                f"0x{k:x}": v for k, v in self.handler_hits.items()
            },
        }

    def to_pseudocode(self) -> str:
        """Convert traced instructions to readable pseudocode."""
        lines = []
        for insn in self.instructions:
            if insn.semantics == "mov":
                if len(insn.operands) >= 2:
                    lines.append(f"r{insn.operands[0]} = r{insn.operands[1]}")
                elif len(insn.operands) == 1:
                    lines.append(f"r{insn.operands[0]} = ???")
            elif insn.semantics == "load":
                if len(insn.operands) >= 2:
                    lines.append(f"r{insn.operands[0]} = mem[r{insn.operands[1]}]")
            elif insn.semantics == "store":
                if len(insn.operands) >= 2:
                    lines.append(f"mem[r{insn.operands[0]}] = r{insn.operands[1]}")
            elif insn.semantics == "add":
                if len(insn.operands) >= 3:
                    lines.append(f"r{insn.operands[0]} = r{insn.operands[1]} + r{insn.operands[2]}")
                elif len(insn.operands) >= 2:
                    lines.append(f"r{insn.operands[0]} += r{insn.operands[1]}")
            elif insn.semantics == "sub":
                if len(insn.operands) >= 3:
                    lines.append(f"r{insn.operands[0]} = r{insn.operands[1]} - r{insn.operands[2]}")
            elif insn.semantics == "mul":
                if len(insn.operands) >= 3:
                    lines.append(f"r{insn.operands[0]} = r{insn.operands[1]} * r{insn.operands[2]}")
            elif insn.semantics in ("and", "or", "xor"):
                op_sym = {"and": "&", "or": "|", "xor": "^"}[insn.semantics]
                if len(insn.operands) >= 3:
                    lines.append(f"r{insn.operands[0]} = r{insn.operands[1]} {op_sym} r{insn.operands[2]}")
            elif insn.semantics == "not":
                if len(insn.operands) >= 2:
                    lines.append(f"r{insn.operands[0]} = ~r{insn.operands[1]}")
            elif insn.semantics == "cmp":
                if len(insn.operands) >= 2:
                    lines.append(f"flags = cmp(r{insn.operands[0]}, r{insn.operands[1]})")
            elif insn.semantics == "branch":
                if len(insn.operands) >= 1:
                    lines.append(f"if flags: goto vm_pc {insn.operands[0]}")
            elif insn.semantics == "jmp":
                if len(insn.operands) >= 1:
                    lines.append(f"goto vm_pc {insn.operands[0]}")
            elif insn.semantics == "call":
                if len(insn.operands) >= 1:
                    lines.append(f"call 0x{insn.operands[0]:x}")
            elif insn.semantics == "ret":
                if len(insn.operands) >= 1:
                    lines.append(f"return r{insn.operands[0]}")
                else:
                    lines.append("return")
            elif insn.semantics == "nop":
                lines.append("nop")
            elif insn.semantics == "push":
                if len(insn.operands) >= 1:
                    lines.append(f"push r{insn.operands[0]}")
            elif insn.semantics == "pop":
                if len(insn.operands) >= 1:
                    lines.append(f"r{insn.operands[0]} = pop()")
            elif insn.semantics == "load_imm":
                if len(insn.operands) >= 2:
                    lines.append(f"r{insn.operands[0]} = {insn.operands[1]}")
            else:
                ops = ", ".join(str(o) for o in insn.operands)
                lines.append(f"{insn.semantics}({ops})")

        return "\n".join(lines)


def trace_bytecode(
    bytecode: bytes,
    handlers: list[dict[str, Any]],
    max_instructions: int = 1000,
) -> VMTrace:
    """Trace VM bytecode execution by simulating the fetch-decode-execute loop.

    Args:
        bytecode: raw bytecode bytes
        handlers: list of {opcode, semantics, operand_count, address}
        max_instructions: safety limit

    Returns:
        VMTrace with recovered instruction sequence
    """
    trace = VMTrace()
    trace.bytecode = bytecode

    handler_map = {}
    for h in handlers:
        handler_map[h["opcode"]] = h

    pc = 0
    for _ in range(max_instructions):
        if pc >= len(bytecode):
            break

        opcode = bytecode[pc]
        handler = handler_map.get(opcode)

        if handler is None:
            # Unknown opcode — record and advance
            trace.add_instruction(VMInstruction(
                pc=pc, opcode=opcode, operands=[],
                handler_addr=0, semantics="unknown",
            ))
            pc += 1
            continue

        operand_count = handler.get("operand_count", 0)
        operands = []
        for i in range(operand_count):
            if pc + 1 + i < len(bytecode):
                operands.append(bytecode[pc + 1 + i])

        insn = VMInstruction(
            pc=pc,
            opcode=opcode,
            operands=operands,
            handler_addr=handler.get("address", 0),
            semantics=handler.get("semantics", "unknown"),
        )
        trace.add_instruction(insn)

        # Check for termination
        if handler.get("semantics") == "ret":
            break

        pc += 1 + operand_count

    return trace


def trace_vm(params: dict[str, Any]) -> dict[str, Any]:
    """Main entry: trace VM bytecode and generate pseudocode.

    Params:
        bytecode_hex: hex-encoded bytecode
        handlers: list of handler descriptors from vm.analyze
        max_instructions: safety limit (default 1000)
    """
    bytecode = bytes.fromhex(params["bytecode_hex"])
    handlers = params["handlers"]
    max_insns = params.get("max_instructions", 1000)

    trace = trace_bytecode(bytecode, handlers, max_insns)
    pseudocode = trace.to_pseudocode()

    return {
        "status": "traced",
        "trace": trace.to_dict(),
        "pseudocode": pseudocode,
        "summary": (
            f"Traced {len(trace.instructions)} VM instructions, "
            f"{len(trace.handler_hits)} unique handlers used"
        ),
    }
