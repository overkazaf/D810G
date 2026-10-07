"""Tests for Capstone-based VM handler classification."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.virtualization.disasm import (
    classify_handler_by_disasm,
    HAS_CAPSTONE,
)
from d810g_engine.virtualization.analyzer import classify_handler


# Skip entire module if capstone is not installed
pytestmark = pytest.mark.skipif(not HAS_CAPSTONE, reason="capstone not available")

BASE_ADDR = 0x400000


def _make_binary(hex_str: str, addr: int = BASE_ADDR) -> tuple[bytes, int]:
    """Build a binary buffer whose bytes start at *addr*."""
    return bytes.fromhex(hex_str), addr


class TestDisasmRetHandler:
    """RET instruction patterns."""

    def test_plain_ret(self):
        # c3 = ret
        binary, base = _make_binary("c3")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "ret"
        assert result["confidence"] == "high"

    def test_mov_then_ret(self):
        # 48 89 d8 = mov rax, rbx;  c3 = ret
        # With RET deprioritized, meaningful ops (mov) take precedence
        binary, base = _make_binary("4889d8c3")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "mov"
        assert result["confidence"] == "medium"


class TestDisasmArithmeticHandlers:
    """ADD / SUB / MUL / DIV patterns."""

    def test_add_reg_reg(self):
        # 48 01 d8 = add rax, rbx
        binary, base = _make_binary("4801d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "add"
        assert result["confidence"] == "high"
        assert result["operand_count"] == 2

    def test_sub_reg_reg(self):
        # 48 29 d8 = sub rax, rbx
        binary, base = _make_binary("4829d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "sub"
        assert result["confidence"] == "high"

    def test_imul_reg_reg(self):
        # 48 0f af c3 = imul rax, rbx
        binary, base = _make_binary("480fafc3")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "mul"
        assert result["confidence"] == "high"


class TestDisasmBitwiseHandlers:
    """AND / OR / XOR / NOT / shift patterns."""

    def test_xor_reg_reg(self):
        # 48 31 d8 = xor rax, rbx
        binary, base = _make_binary("4831d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "xor"
        assert result["confidence"] == "high"

    def test_and_reg_reg(self):
        # 48 21 d8 = and rax, rbx
        binary, base = _make_binary("4821d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "and"
        assert result["confidence"] == "high"

    def test_or_reg_reg(self):
        # 48 09 d8 = or rax, rbx
        binary, base = _make_binary("4809d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "or"
        assert result["confidence"] == "high"

    def test_not_reg(self):
        # 48 f7 d0 = not rax
        binary, base = _make_binary("48f7d0")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "not"
        assert result["confidence"] == "high"

    def test_shl_reg_imm(self):
        # 48 c1 e0 04 = shl rax, 4
        binary, base = _make_binary("48c1e004")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "shift"
        assert result["confidence"] == "high"


class TestDisasmCompareAndBranch:
    """CMP / TEST with or without conditional jumps."""

    def test_cmp_then_jne(self):
        # 48 39 d8 = cmp rax, rbx;  75 02 = jne +2
        binary, base = _make_binary("4839d87502")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "cmp_branch"
        assert result["confidence"] == "high"

    def test_cmp_alone(self):
        # 48 39 d8 = cmp rax, rbx  (no jump follows in this snippet)
        binary, base = _make_binary("4839d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "cmp"
        assert result["confidence"] == "medium"

    def test_test_then_je(self):
        # 48 85 c0 = test rax, rax;  74 02 = je +2
        binary, base = _make_binary("4885c07402")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "cmp_branch"
        assert result["confidence"] == "high"


class TestDisasmCallHandler:
    """CALL instruction patterns."""

    def test_call_relative(self):
        # e8 00 00 00 00 = call next (relative 0)
        binary, base = _make_binary("e800000000")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "call"
        assert result["confidence"] == "high"


class TestDisasmStackHandlers:
    """PUSH / POP patterns."""

    def test_push_reg(self):
        # 50 = push rax
        binary, base = _make_binary("50")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "push"
        assert result["confidence"] == "high"

    def test_pop_reg(self):
        # 58 = pop rax
        binary, base = _make_binary("58")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "pop"
        assert result["confidence"] == "high"


class TestDisasmNop:
    """NOP instruction."""

    def test_nop(self):
        # 90 = nop
        binary, base = _make_binary("90")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "nop"
        assert result["confidence"] == "high"


class TestDisasmMovHandler:
    """Register-to-register MOV without memory or arithmetic."""

    def test_mov_reg_reg(self):
        # 48 89 d8 = mov rax, rbx
        binary, base = _make_binary("4889d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "mov"
        assert result["confidence"] == "medium"


class TestDisasmMemoryHandlers:
    """Load / store patterns."""

    def test_load_from_memory(self):
        # 48 8b 03 = mov rax, qword ptr [rbx]
        binary, base = _make_binary("488b03")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "load"
        assert result["confidence"] == "medium"

    def test_store_to_memory(self):
        # 48 89 03 = mov qword ptr [rbx], rax
        binary, base = _make_binary("488903")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "store"
        assert result["confidence"] == "medium"

    def test_load_immediate(self):
        # 48 c7 c0 2a 00 00 00 = mov rax, 0x2a
        binary, base = _make_binary("48c7c02a000000")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert result["semantics"] == "load_imm"
        assert result["confidence"] == "medium"


class TestDisasmEdgeCases:
    """Error handling and edge cases."""

    def test_address_out_of_range(self):
        binary, base = _make_binary("90")
        result = classify_handler_by_disasm(BASE_ADDR + 0x1000, binary, base)
        assert result["semantics"] == "unknown"
        assert result["confidence"] == "none"

    def test_empty_binary(self):
        result = classify_handler_by_disasm(BASE_ADDR, b"", BASE_ADDR)
        assert result["semantics"] == "unknown"
        assert result["confidence"] == "none"

    def test_unsupported_arch(self):
        binary, base = _make_binary("90")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base, arch="mips")
        assert result["semantics"] == "unknown"
        assert result["confidence"] == "none"

    def test_invalid_bytes(self):
        # ff ff is not a valid instruction prefix in most contexts, but
        # Capstone may still decode something. We just verify no crash.
        binary, base = _make_binary("ffff")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert "semantics" in result


class TestDisasmIntegration:
    """Integration: classify_handler uses disasm when bytes are available."""

    def test_classify_handler_uses_disasm(self):
        """When binary bytes contain real instructions, disasm path wins."""
        # 48 01 d8 = add rax, rbx
        blocks = [{"addr": BASE_ADDR, "insn_count": 1, "succs": [BASE_ADDR + 3]}]
        binary = bytes.fromhex("4801d8")
        handler = classify_handler(BASE_ADDR, blocks, binary, BASE_ADDR)
        assert handler.semantics == "add"
        assert handler.description == "Integer addition"

    def test_classify_handler_falls_back_to_heuristic(self):
        """Empty binary bytes triggers the heuristic path."""
        blocks = [{"addr": 0x1500, "insn_count": 2, "succs": []}]
        handler = classify_handler(0x1500, blocks, b"", 0)
        assert handler.semantics == "ret"

    def test_classify_handler_ret_via_disasm(self):
        """RET instruction classified via disasm path."""
        blocks = [{"addr": BASE_ADDR, "insn_count": 1, "succs": []}]
        binary = bytes.fromhex("c3")
        handler = classify_handler(BASE_ADDR, blocks, binary, BASE_ADDR)
        assert handler.semantics == "ret"

    def test_classify_handler_xor_via_disasm(self):
        """XOR instruction classified via disasm path."""
        # 48 31 d8 = xor rax, rbx
        blocks = [{"addr": BASE_ADDR, "insn_count": 1, "succs": [BASE_ADDR + 3]}]
        binary = bytes.fromhex("4831d8")
        handler = classify_handler(BASE_ADDR, blocks, binary, BASE_ADDR)
        assert handler.semantics == "xor"
        assert handler.operand_count == 2


class TestDisasmResultStructure:
    """Verify all result dicts contain the expected keys."""

    def test_result_has_disassembly(self):
        binary, base = _make_binary("4801d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert "disassembly" in result
        assert isinstance(result["disassembly"], list)
        assert len(result["disassembly"]) > 0

    def test_result_has_instruction_count(self):
        binary, base = _make_binary("4801d8")
        result = classify_handler_by_disasm(BASE_ADDR, binary, base)
        assert "instruction_count" in result
        assert result["instruction_count"] >= 1
