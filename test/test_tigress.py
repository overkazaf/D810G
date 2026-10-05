import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.deflattener.tigress import detect_tigress_pattern, deflat_tigress


class TestTigressDetection:

    def test_detect_indirect_jump_table(self):
        """Tigress indirect jump: dispatcher uses jmp [table + state*8]"""
        blocks = [
            {
                "addr": 0x1000,
                "has_indirect_jump": True,
                "jump_table": [0x1100, 0x1200, 0x1300, 0x1400],
                "succs": [0x1100, 0x1200, 0x1300, 0x1400],
            },
            {"addr": 0x1100, "state_update": 1, "succs": [0x1000]},
            {"addr": 0x1200, "state_update": 2, "succs": [0x1000]},
            {"addr": 0x1300, "state_update": 3, "succs": [0x1000]},
            {"addr": 0x1400, "succs": []},  # return block
        ]
        result = detect_tigress_pattern(blocks)
        assert result is not None
        assert result["type"] == "tigress_indirect"
        assert result["dispatcher"] == 0x1000
        assert len(result["case_blocks"]) == 3
        assert len(result["jump_table"]) == 4

    def test_detect_if_chain(self):
        """Tigress if-chain: dispatcher uses sequential if/else."""
        blocks = [
            {"addr": 0x1000, "compares_state": True, "succs": [0x1100, 0x1010]},
            {"addr": 0x1010, "compares_state": True, "succs": [0x1200, 0x1020]},
            {"addr": 0x1020, "compares_state": True, "succs": [0x1300, 0x1400]},
            {"addr": 0x1100, "state_update": 0xAA, "succs": [0x1000]},
            {"addr": 0x1200, "state_update": 0xBB, "succs": [0x1000]},
            {"addr": 0x1300, "state_update": 0xCC, "succs": [0x1000]},
            {"addr": 0x1400, "succs": []},  # return
        ]
        result = detect_tigress_pattern(blocks)
        assert result is not None
        assert result["type"] == "tigress_ifchain"
        assert len(result["case_blocks"]) >= 2
        assert len(result["chain_blocks"]) == 3

    def test_no_pattern_in_normal_code(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": [0x1020, 0x1030]},
            {"addr": 0x1020, "succs": [0x1040]},
            {"addr": 0x1030, "succs": [0x1040]},
            {"addr": 0x1040, "succs": []},
        ]
        result = detect_tigress_pattern(blocks)
        assert result is None


class TestTigressDeflattening:

    def test_deflat_indirect_jump(self):
        result = deflat_tigress({
            "blocks": [
                {
                    "addr": 0x1000,
                    "has_indirect_jump": True,
                    "jump_table": [0x1100, 0x1200, 0x1300],
                    "succs": [0x1100, 0x1200, 0x1300],
                },
                {"addr": 0x1100, "state_update": 1, "succs": [0x1000]},
                {"addr": 0x1200, "state_update": 2, "succs": [0x1000]},
                {"addr": 0x1300, "succs": []},
            ],
            "binary_hex": "90" * 100,
        })
        assert result["status"] == "deobfuscated"
        assert result["pattern"]["type"] == "tigress_indirect"
        assert len(result["transitions"]) >= 2

    def test_deflat_no_pattern(self):
        result = deflat_tigress({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1010]},
                {"addr": 0x1010, "succs": []},
            ],
            "binary_hex": "c3",
        })
        assert result["status"] == "no_cff_detected"

    def test_handler_registration(self):
        """Verify tigress handler registers on server."""
        from d810g_engine.server import Server
        from d810g_engine.deflattener import register_handlers
        server = Server()
        register_handlers(server)
        assert "deflat.tigress" in server._handlers
