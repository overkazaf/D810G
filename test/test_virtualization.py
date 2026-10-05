import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.virtualization.analyzer import (
    detect_vm_dispatcher,
    classify_handler,
    analyze_vm,
    VMHandler,
    VMContext,
)


class TestVMDispatcherDetection:

    def test_detect_vm_pattern(self):
        """Classic VM: dispatcher with many handlers that loop back."""
        blocks = [
            {"addr": 0x1000, "succs": [0x1100, 0x1200, 0x1300, 0x1400, 0x1500]},
            {"addr": 0x1100, "succs": [0x1000], "insn_count": 3},
            {"addr": 0x1200, "succs": [0x1000], "insn_count": 4},
            {"addr": 0x1300, "succs": [0x1000], "insn_count": 3},
            {"addr": 0x1400, "succs": [0x1000], "insn_count": 5},
            {"addr": 0x1500, "succs": [], "insn_count": 2},
        ]
        result = detect_vm_dispatcher(blocks)
        assert result is not None
        assert result["dispatcher_addr"] == 0x1000
        assert result["handler_count"] == 5

    def test_no_vm_in_normal_code(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": [0x1020, 0x1030]},
            {"addr": 0x1020, "succs": [0x1040]},
            {"addr": 0x1030, "succs": [0x1040]},
            {"addr": 0x1040, "succs": []},
        ]
        result = detect_vm_dispatcher(blocks)
        assert result is None

    def test_no_vm_too_few_blocks(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": []},
        ]
        result = detect_vm_dispatcher(blocks)
        assert result is None


class TestHandlerClassification:

    def test_classify_ret_handler(self):
        blocks = [{"addr": 0x1500, "insn_count": 2, "succs": []}]
        handler = classify_handler(0x1500, blocks, b"", 0)
        assert handler.semantics == "ret"

    def test_classify_mov_handler(self):
        blocks = [{"addr": 0x1100, "insn_count": 3, "succs": [0x1000],
                    "has_memory_access": False, "has_arithmetic": False}]
        handler = classify_handler(0x1100, blocks, b"", 0)
        assert handler.semantics == "mov"

    def test_classify_arithmetic_handler(self):
        blocks = [{"addr": 0x1200, "insn_count": 3, "succs": [0x1000],
                    "has_memory_access": False, "has_arithmetic": True}]
        handler = classify_handler(0x1200, blocks, b"", 0)
        assert handler.semantics == "add"

    def test_classify_branch_handler(self):
        blocks = [{"addr": 0x1300, "insn_count": 4, "succs": [0x1000, 0x1400]}]
        handler = classify_handler(0x1300, blocks, b"", 0)
        assert handler.semantics == "branch"

    def test_classify_unknown(self):
        handler = classify_handler(0x9999, [], b"", 0)
        assert handler.semantics == "unknown"


class TestVMAnalysisPipeline:

    def test_full_pipeline_vm_detected(self):
        result = analyze_vm({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1100, 0x1200, 0x1300, 0x1400]},
                {"addr": 0x1100, "succs": [0x1000], "insn_count": 3,
                 "has_memory_access": False, "has_arithmetic": False},
                {"addr": 0x1200, "succs": [0x1000], "insn_count": 3,
                 "has_memory_access": False, "has_arithmetic": True},
                {"addr": 0x1300, "succs": [0x1000, 0x1400], "insn_count": 4},
                {"addr": 0x1400, "succs": [], "insn_count": 2},
            ],
            "binary_hex": "90" * 100,
        })
        assert result["status"] == "vm_detected"
        assert result["context"]["handler_count"] == 4
        assert "summary" in result

    def test_full_pipeline_no_vm(self):
        result = analyze_vm({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1010]},
                {"addr": 0x1010, "succs": []},
            ],
            "binary_hex": "c3",
        })
        assert result["status"] == "no_vm_detected"

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.virtualization import register_handlers
        server = Server()
        register_handlers(server)
        assert "vm.analyze" in server._handlers


class TestVMDataClasses:

    def test_vm_handler_to_dict(self):
        h = VMHandler(opcode=0x01, address=0x1100, semantics="mov", operand_count=2)
        d = h.to_dict()
        assert d["opcode"] == 1
        assert d["opcode_hex"] == "0x01"
        assert d["semantics"] == "mov"

    def test_vm_context_to_dict(self):
        ctx = VMContext()
        ctx.dispatcher_addr = 0x1000
        ctx.handlers.append(VMHandler(0, 0x1100, "mov", 2))
        ctx.handlers.append(VMHandler(1, 0x1200, "add", 2))
        d = ctx.to_dict()
        assert d["handler_count"] == 2
        assert len(d["handlers"]) == 2
