import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.dce.eliminator import (
    find_reachable_blocks,
    find_dead_blocks,
    generate_nop_patches,
    compute_dce_stats,
    eliminate_dead_code,
)


class TestReachability:

    def test_all_reachable(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": [0x1020]},
            {"addr": 0x1020, "succs": []},
        ]
        reachable = find_reachable_blocks(blocks, 0x1000)
        assert reachable == {0x1000, 0x1010, 0x1020}

    def test_dead_block(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1020]},  # skips 0x1010
            {"addr": 0x1010, "succs": [0x1020]},   # unreachable
            {"addr": 0x1020, "succs": []},
        ]
        reachable = find_reachable_blocks(blocks, 0x1000)
        assert 0x1010 not in reachable

    def test_branch_both_reachable(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1010, 0x1020]},
            {"addr": 0x1010, "succs": [0x1030]},
            {"addr": 0x1020, "succs": [0x1030]},
            {"addr": 0x1030, "succs": []},
        ]
        reachable = find_reachable_blocks(blocks, 0x1000)
        assert len(reachable) == 4

    def test_cycle(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": [0x1000]},  # back-edge
        ]
        reachable = find_reachable_blocks(blocks, 0x1000)
        assert reachable == {0x1000, 0x1010}


class TestDeadBlockDetection:

    def test_find_dead_after_bcf(self):
        """After BCF removal, bogus blocks become unreachable."""
        blocks = [
            {"addr": 0x1000, "succs": [0x1100], "size": 16},          # was conditional, now unconditional
            {"addr": 0x1100, "succs": [0x1300], "size": 32},          # real block
            {"addr": 0x1200, "succs": [0x1300], "size": 48},          # bogus (dead)
            {"addr": 0x1300, "succs": [], "size": 8},                  # return
        ]
        dead = find_dead_blocks(blocks, 0x1000)
        assert len(dead) == 1
        assert dead[0]["addr"] == 0x1200

    def test_multiple_dead_blocks(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1030], "size": 8},
            {"addr": 0x1010, "succs": [0x1020], "size": 16},  # dead
            {"addr": 0x1020, "succs": [0x1030], "size": 16},  # dead
            {"addr": 0x1030, "succs": [], "size": 4},
        ]
        dead = find_dead_blocks(blocks, 0x1000)
        assert len(dead) == 2

    def test_no_dead_blocks(self):
        blocks = [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": []},
        ]
        dead = find_dead_blocks(blocks, 0x1000)
        assert len(dead) == 0


class TestNOPPatching:

    def test_x86_nop_patch(self):
        dead = [{"addr": 0x1200, "size": 4}]
        patches = generate_nop_patches(dead, "x86_64")
        assert len(patches) == 1
        assert patches[0]["bytes"] == "90909090"

    def test_arm64_nop_patch(self):
        dead = [{"addr": 0x1200, "size": 8}]
        patches = generate_nop_patches(dead, "aarch64")
        assert len(patches) == 1
        assert patches[0]["bytes"] == "1f2003d5" * 2

    def test_arm32_nop_patch(self):
        dead = [{"addr": 0x1200, "size": 4}]
        patches = generate_nop_patches(dead, "arm")
        assert len(patches) == 1
        assert patches[0]["bytes"] == "0000a0e1"


class TestDCEStats:

    def test_stats_calculation(self):
        blocks = [
            {"addr": 0x1000, "size": 16},
            {"addr": 0x1010, "size": 32},
            {"addr": 0x1020, "size": 8},
        ]
        dead = [{"addr": 0x1010, "size": 32}]
        stats = compute_dce_stats(blocks, dead)
        assert stats["total_blocks"] == 3
        assert stats["dead_blocks"] == 1
        assert stats["live_blocks"] == 2
        assert stats["dead_bytes"] == 32
        assert stats["reduction_pct"] == 33.3


class TestDCEPipeline:

    def test_full_pipeline(self):
        result = eliminate_dead_code({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1100], "size": 16},
                {"addr": 0x1100, "succs": [0x1300], "size": 32},
                {"addr": 0x1200, "succs": [0x1300], "size": 48},  # dead
                {"addr": 0x1300, "succs": [], "size": 8},
            ],
            "entry_addr": 0x1000,
        })
        assert result["status"] == "dead_code_eliminated"
        assert len(result["dead_blocks"]) == 1
        assert len(result["patches"]) == 1
        assert result["stats"]["dead_blocks"] == 1

    def test_no_dead_code_pipeline(self):
        result = eliminate_dead_code({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1010], "size": 8},
                {"addr": 0x1010, "succs": [], "size": 4},
            ],
            "entry_addr": 0x1000,
        })
        assert result["status"] == "no_dead_code"

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.dce import register_handlers
        server = Server()
        register_handlers(server)
        assert "dce.run" in server._handlers
