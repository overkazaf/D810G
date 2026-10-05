import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.bcf.detector import (
    detect_bcf_candidates,
    generate_bcf_patches,
    detect_and_remove_bcf,
)


class TestBCFDetection:

    def test_detect_always_true_bcf(self):
        """BCF with always-true opaque predicate: real=true_target, bogus=false_target."""
        blocks = [
            {
                "addr": 0x1000,
                "condition": "x == x",
                "succs": [0x1100, 0x1200],
            },
            {"addr": 0x1100, "succs": [0x1300]},   # real block
            {"addr": 0x1200, "succs": [0x1300]},   # bogus block
            {"addr": 0x1300, "succs": []},          # convergence
        ]
        candidates = detect_bcf_candidates(blocks)
        assert len(candidates) == 1
        assert candidates[0]["classification"] == "always_true"
        assert candidates[0]["real_target"] == 0x1100
        assert candidates[0]["bogus_target"] == 0x1200

    def test_detect_always_false_bcf(self):
        """BCF with always-false opaque predicate: real=false_target, bogus=true_target."""
        blocks = [
            {
                "addr": 0x1000,
                "condition": "(x & 1) == 2",
                "succs": [0x1100, 0x1200],
            },
            {"addr": 0x1100, "succs": [0x1300]},   # bogus (true branch of always-false)
            {"addr": 0x1200, "succs": [0x1300]},   # real block
            {"addr": 0x1300, "succs": []},
        ]
        candidates = detect_bcf_candidates(blocks)
        assert len(candidates) == 1
        assert candidates[0]["classification"] == "always_false"
        assert candidates[0]["real_target"] == 0x1200
        assert candidates[0]["bogus_target"] == 0x1100

    def test_no_bcf_dynamic_condition(self):
        """Real conditional branches should not be flagged as BCF."""
        blocks = [
            {
                "addr": 0x1000,
                "condition": "x > 5",
                "succs": [0x1100, 0x1200],
            },
            {"addr": 0x1100, "succs": [0x1300]},
            {"addr": 0x1200, "succs": [0x1300]},
            {"addr": 0x1300, "succs": []},
        ]
        candidates = detect_bcf_candidates(blocks)
        assert len(candidates) == 0

    def test_no_bcf_no_convergence(self):
        """Branches that don't converge are not BCF."""
        blocks = [
            {
                "addr": 0x1000,
                "condition": "x == x",
                "succs": [0x1100, 0x1200],
            },
            {"addr": 0x1100, "succs": [0x1300]},
            {"addr": 0x1200, "succs": [0x1400]},   # different target
            {"addr": 0x1300, "succs": []},
            {"addr": 0x1400, "succs": []},
        ]
        candidates = detect_bcf_candidates(blocks)
        assert len(candidates) == 0

    def test_no_bcf_no_condition(self):
        """Blocks without conditions can't be BCF."""
        blocks = [
            {"addr": 0x1000, "succs": [0x1100, 0x1200]},
            {"addr": 0x1100, "succs": [0x1300]},
            {"addr": 0x1200, "succs": [0x1300]},
            {"addr": 0x1300, "succs": []},
        ]
        candidates = detect_bcf_candidates(blocks)
        assert len(candidates) == 0


class TestBCFPatchGeneration:

    def test_generate_patches(self):
        candidates = [
            {
                "branch_addr": 0x1000,
                "condition": "x == x",
                "classification": "always_true",
                "real_target": 0x1100,
                "bogus_target": 0x1200,
                "convergence_point": 0x1300,
            }
        ]
        patches = generate_bcf_patches(candidates)
        assert len(patches) == 1
        assert patches[0]["address"] == 0x1000
        assert patches[0]["target"] == 0x1100
        assert patches[0]["action"] == "force_unconditional"


class TestBCFFullPipeline:

    def test_full_pipeline_with_bcf(self):
        result = detect_and_remove_bcf({
            "blocks": [
                {"addr": 0x1000, "condition": "x == x", "succs": [0x1100, 0x1200]},
                {"addr": 0x1100, "succs": [0x1300]},
                {"addr": 0x1200, "succs": [0x1300]},
                {"addr": 0x1300, "succs": []},
            ],
        })
        assert result["status"] == "bcf_removed"
        assert len(result["candidates"]) == 1
        assert len(result["patches"]) == 1

    def test_full_pipeline_no_bcf(self):
        result = detect_and_remove_bcf({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1100]},
                {"addr": 0x1100, "succs": []},
            ],
        })
        assert result["status"] == "no_bcf_detected"

    def test_multiple_bcf_blocks(self):
        """Function with multiple BCF-inserted branches."""
        result = detect_and_remove_bcf({
            "blocks": [
                {"addr": 0x1000, "condition": "x == x", "succs": [0x1100, 0x1200]},
                {"addr": 0x1100, "succs": [0x1300]},
                {"addr": 0x1200, "succs": [0x1300]},
                {"addr": 0x1300, "condition": "(x & 1) == 2", "succs": [0x1400, 0x1500]},
                {"addr": 0x1400, "succs": [0x1600]},
                {"addr": 0x1500, "succs": [0x1600]},
                {"addr": 0x1600, "succs": []},
            ],
        })
        assert result["status"] == "bcf_removed"
        assert len(result["candidates"]) == 2
        assert len(result["patches"]) == 2

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.bcf import register_handlers
        server = Server()
        register_handlers(server)
        assert "bcf.run" in server._handlers
