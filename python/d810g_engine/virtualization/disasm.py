"""Disassembly-based VM handler classification using Capstone."""

from __future__ import annotations
from typing import Any

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_ARM
    from capstone import CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    from capstone.x86_const import (
        X86_INS_MOV, X86_INS_MOVZX, X86_INS_MOVSX, X86_INS_LEA,
        X86_INS_ADD, X86_INS_SUB, X86_INS_MUL, X86_INS_IMUL, X86_INS_DIV, X86_INS_IDIV,
        X86_INS_AND, X86_INS_OR, X86_INS_XOR, X86_INS_NOT, X86_INS_NEG,
        X86_INS_SHL, X86_INS_SHR, X86_INS_SAR,
        X86_INS_CMP, X86_INS_TEST,
        X86_INS_PUSH, X86_INS_POP,
        X86_INS_JMP, X86_INS_CALL, X86_INS_RET,
        X86_INS_NOP,
        X86_OP_MEM, X86_OP_REG, X86_OP_IMM,
    )
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# Instruction categories
MOVE_INSNS = {X86_INS_MOV, X86_INS_MOVZX, X86_INS_MOVSX, X86_INS_LEA} if HAS_CAPSTONE else set()
ARITH_INSNS = {X86_INS_ADD, X86_INS_SUB, X86_INS_MUL, X86_INS_IMUL, X86_INS_DIV, X86_INS_IDIV} if HAS_CAPSTONE else set()
BITWISE_INSNS = {X86_INS_AND, X86_INS_OR, X86_INS_XOR, X86_INS_NOT, X86_INS_NEG, X86_INS_SHL, X86_INS_SHR, X86_INS_SAR} if HAS_CAPSTONE else set()
CMP_INSNS = {X86_INS_CMP, X86_INS_TEST} if HAS_CAPSTONE else set()
STACK_INSNS = {X86_INS_PUSH, X86_INS_POP} if HAS_CAPSTONE else set()


def classify_handler_by_disasm(
    handler_addr: int,
    binary_bytes: bytes,
    base_addr: int,
    arch: str = "x86_64",
    max_insns: int = 20,
) -> dict[str, Any]:
    """Classify a VM handler by disassembling its code.

    Returns:
        {semantics, operand_count, description, instructions, confidence}
    """
    if not HAS_CAPSTONE:
        return {"semantics": "unknown", "confidence": "none", "reason": "capstone not available"}

    # Set up disassembler
    if "x86" in arch.lower() or "x64" in arch.lower():
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
    elif "aarch64" in arch.lower() or "arm64" in arch.lower():
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif "arm" in arch.lower():
        cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    else:
        return {"semantics": "unknown", "confidence": "none", "reason": f"unsupported arch: {arch}"}

    cs.detail = True

    # Extract handler bytes
    offset = handler_addr - base_addr
    if offset < 0 or offset >= len(binary_bytes):
        return {"semantics": "unknown", "confidence": "none", "reason": "address out of range"}

    handler_bytes = binary_bytes[offset:offset + max_insns * 15]  # max 15 bytes per x86 insn

    # Disassemble
    instructions = list(cs.disasm(handler_bytes, handler_addr))
    if not instructions:
        return {"semantics": "unknown", "confidence": "none", "reason": "no instructions decoded"}

    # Analyze instruction mix
    insn_ids = [insn.id for insn in instructions]

    has_ret = any(i.id == X86_INS_RET for i in instructions)
    has_call = any(i.id == X86_INS_CALL for i in instructions)
    has_cmp = any(i.id in CMP_INSNS for i in instructions)
    has_jmp = any(CS_GRP_JUMP in i.groups for i in instructions if i.groups)

    move_count = sum(1 for i in insn_ids if i in MOVE_INSNS)
    arith_count = sum(1 for i in insn_ids if i in ARITH_INSNS)
    bitwise_count = sum(1 for i in insn_ids if i in BITWISE_INSNS)
    stack_count = sum(1 for i in insn_ids if i in STACK_INSNS)

    # Check for memory access patterns
    has_load = False
    has_store = False
    for insn in instructions:
        if insn.id in MOVE_INSNS and len(insn.operands) >= 2:
            if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM:
                has_load = True
            elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_REG:
                has_store = True

    has_imm_load = False
    for insn in instructions:
        if insn.id in MOVE_INSNS and len(insn.operands) >= 2:
            if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
                has_imm_load = True

    # Classification logic
    total_meaningful = move_count + arith_count + bitwise_count + stack_count

    result = {
        "instruction_count": len(instructions),
        "disassembly": [f"{i.mnemonic} {i.op_str}" for i in instructions[:10]],
    }

    if has_ret and total_meaningful <= 2:
        result.update(semantics="ret", operand_count=1, confidence="high",
                      description="Return from VM (contains RET instruction)")
    elif has_call:
        result.update(semantics="call", operand_count=1, confidence="high",
                      description="Native function call")
    elif has_cmp and has_jmp:
        result.update(semantics="cmp_branch", operand_count=2, confidence="high",
                      description="Compare and conditional branch")
    elif has_cmp:
        result.update(semantics="cmp", operand_count=2, confidence="medium",
                      description="Comparison (sets flags)")
    elif arith_count > 0 and arith_count >= bitwise_count:
        # Determine specific arithmetic op
        if any(i in insn_ids for i in [X86_INS_ADD]):
            result.update(semantics="add", operand_count=2, confidence="high",
                          description="Integer addition")
        elif any(i in insn_ids for i in [X86_INS_SUB]):
            result.update(semantics="sub", operand_count=2, confidence="high",
                          description="Integer subtraction")
        elif any(i in insn_ids for i in [X86_INS_MUL, X86_INS_IMUL]):
            result.update(semantics="mul", operand_count=2, confidence="high",
                          description="Integer multiplication")
        elif any(i in insn_ids for i in [X86_INS_DIV, X86_INS_IDIV]):
            result.update(semantics="div", operand_count=2, confidence="high",
                          description="Integer division")
        else:
            result.update(semantics="arithmetic", operand_count=2, confidence="medium",
                          description="Generic arithmetic operation")
    elif bitwise_count > 0:
        if X86_INS_AND in insn_ids:
            result.update(semantics="and", operand_count=2, confidence="high",
                          description="Bitwise AND")
        elif X86_INS_OR in insn_ids:
            result.update(semantics="or", operand_count=2, confidence="high",
                          description="Bitwise OR")
        elif X86_INS_XOR in insn_ids:
            result.update(semantics="xor", operand_count=2, confidence="high",
                          description="Bitwise XOR")
        elif X86_INS_NOT in insn_ids:
            result.update(semantics="not", operand_count=1, confidence="high",
                          description="Bitwise NOT")
        elif any(i in insn_ids for i in [X86_INS_SHL, X86_INS_SHR, X86_INS_SAR]):
            result.update(semantics="shift", operand_count=2, confidence="high",
                          description="Bit shift operation")
        else:
            result.update(semantics="bitwise", operand_count=2, confidence="medium",
                          description="Generic bitwise operation")
    elif has_load and not has_store and not arith_count:
        result.update(semantics="load", operand_count=2, confidence="medium",
                      description="Load from memory to register")
    elif has_store and not arith_count:
        result.update(semantics="store", operand_count=2, confidence="medium",
                      description="Store from register to memory")
    elif has_imm_load and move_count <= 3:
        result.update(semantics="load_imm", operand_count=2, confidence="medium",
                      description="Load immediate value to register")
    elif move_count > 0 and total_meaningful == move_count:
        result.update(semantics="mov", operand_count=2, confidence="medium",
                      description="Register-to-register move")
    elif stack_count > 0 and total_meaningful == stack_count:
        if X86_INS_PUSH in insn_ids:
            result.update(semantics="push", operand_count=1, confidence="high",
                          description="Push to VM stack")
        else:
            result.update(semantics="pop", operand_count=1, confidence="high",
                          description="Pop from VM stack")
    elif instructions[0].id == X86_INS_NOP:
        result.update(semantics="nop", operand_count=0, confidence="high",
                      description="No operation")
    else:
        result.update(semantics="unknown", operand_count=0, confidence="low",
                      description="Unclassified handler")

    return result
