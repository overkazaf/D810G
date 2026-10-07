import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.pipeline.orchestrator import (
    PipelinePass, PipelineResult, build_pipeline, run_pipeline,
    _apply_pass_effects,
)


class TestPipelinePass:

    def test_pass_runs_handler(self):
        handler = lambda p: {"status": "ok", "patches": [{"addr": 1}]}
        p = PipelinePass("test", handler, "test pass")
        result = p.run({})
        assert result["status"] == "ok"
        assert len(result["patches"]) == 1


class TestPipelineResult:

    def test_accumulates_results(self):
        result = PipelineResult()
        result.add_pass_result("pass1", {"status": "ok", "patches": [1, 2]}, 10.0)
        result.add_pass_result("pass2", {"status": "ok", "patches": [3]}, 5.0)
        d = result.to_dict()
        assert d["total_patches"] == 3
        assert d["total_passes"] == 2
        assert d["total_time_ms"] == 15.0


class TestBuildPipeline:

    def test_pipeline_has_all_passes(self):
        passes = build_pipeline()
        names = [p.name for p in passes]
        assert "deflat_ollvm" in names
        assert "deflat_tigress" in names
        assert "bcf" in names
        assert "opaque" in names
        assert "dce" in names
        assert "strings" in names

    def test_pipeline_order(self):
        """Deflattening should come before DCE."""
        passes = build_pipeline()
        names = [p.name for p in passes]
        assert names.index("deflat_ollvm") < names.index("dce")
        assert names.index("bcf") < names.index("dce")


class TestRunPipeline:

    def test_basic_pipeline_run(self):
        result = run_pipeline({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1010], "size": 8},
                {"addr": 0x1010, "succs": [], "size": 4},
            ],
            "binary_hex": "90" * 20,
            "entry_addr": 0x1000,
        })
        assert result["status"] == "completed"
        assert "iterations" in result
        assert "total_patches" in result
        assert result["fixpoint"] is True

    def test_pipeline_with_bcf(self):
        result = run_pipeline({
            "blocks": [
                {"addr": 0x1000, "condition": "x == x",
                 "succs": [0x1100, 0x1200], "size": 16},
                {"addr": 0x1100, "succs": [0x1300], "size": 32},
                {"addr": 0x1200, "succs": [0x1300], "size": 48},
                {"addr": 0x1300, "succs": [], "size": 8},
            ],
            "binary_hex": "90" * 200,
            "entry_addr": 0x1000,
        })
        assert result["status"] == "completed"
        assert result["total_patches"] >= 1

    def test_selective_passes(self):
        result = run_pipeline({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1010]},
                {"addr": 0x1010, "succs": []},
            ],
            "binary_hex": "90" * 20,
            "passes": ["bcf", "dce"],
        })
        assert result["status"] == "completed"
        pass_names = [p["name"] for p in result["passes"]]
        assert "deflat_ollvm" not in pass_names

    def test_max_iterations(self):
        result = run_pipeline({
            "blocks": [
                {"addr": 0x1000, "succs": [0x1010]},
                {"addr": 0x1010, "succs": []},
            ],
            "binary_hex": "90" * 20,
            "max_iterations": 1,
        })
        assert result["iterations"] <= 1

    def test_pipeline_deduplicates_patches(self):
        """Patches found in iteration 1 should not appear again in iteration 2."""
        result = run_pipeline({
            "blocks": [
                {"addr": 0x1000, "condition": "x == x",
                 "succs": [0x1100, 0x1200], "size": 16},
                {"addr": 0x1100, "succs": [0x1300], "size": 32},
                {"addr": 0x1200, "succs": [0x1300], "size": 48},
                {"addr": 0x1300, "succs": [], "size": 8},
            ],
            "binary_hex": "90" * 200,
            "entry_addr": 0x1000,
            "max_iterations": 3,
        })
        assert result["fixpoint"] is True
        # BCF should produce exactly 1 patch, not 3 (one per iteration)
        bcf_patches = sum(p["patches"] for p in result["passes"] if p["name"] == "bcf")
        assert bcf_patches == 1
        # DCE should produce exactly 1 patch (the bogus block), not 3
        dce_patches = sum(p["patches"] for p in result["passes"] if p["name"] == "dce")
        assert dce_patches == 1

    def test_pipeline_converges_in_two_iterations(self):
        """Pipeline should reach fixpoint after iteration 2 finds no new patches."""
        result = run_pipeline({
            "blocks": [
                {"addr": 0x1000, "condition": "x == x",
                 "succs": [0x1100, 0x1200], "size": 16},
                {"addr": 0x1100, "succs": [0x1300], "size": 32},
                {"addr": 0x1200, "succs": [0x1300], "size": 48},
                {"addr": 0x1300, "succs": [], "size": 8},
            ],
            "binary_hex": "90" * 200,
            "entry_addr": 0x1000,
            "max_iterations": 5,
        })
        assert result["iterations"] == 2
        assert result["total_patches"] == 2

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.pipeline import register_handlers
        server = Server()
        register_handlers(server)
        assert "pipeline.run" in server._handlers


class TestApplyPassEffects:

    def test_bcf_updates_successors(self):
        blocks = [
            {"addr": 0x1000, "condition": "x == x", "succs": [0x1100, 0x1200]},
            {"addr": 0x1100, "succs": [0x1300]},
            {"addr": 0x1200, "succs": [0x1300]},
        ]
        result = {
            "candidates": [
                {"branch_addr": 0x1000, "real_target": 0x1100, "bogus_target": 0x1200},
            ],
            "patches": [{"address": 0x1000, "action": "force_unconditional", "target": 0x1100}],
        }
        _apply_pass_effects(blocks, "bcf", result)
        assert blocks[0]["succs"] == [0x1100]
        assert "condition" not in blocks[0]

    def test_opaque_removes_condition(self):
        blocks = [
            {"addr": 0x2000, "condition": "x*x >= 0", "succs": [0x2100, 0x2200]},
        ]
        result = {
            "results": [{"address": 0x2000, "classification": "always_true"}],
            "patches": [{"address": 0x2000, "action": "force_true"}],
        }
        _apply_pass_effects(blocks, "opaque", result)
        assert "condition" not in blocks[0]

    def test_dce_removes_dead_blocks(self):
        blocks = [
            {"addr": 0x3000, "succs": [0x3100]},
            {"addr": 0x3100, "succs": []},
            {"addr": 0x3200, "succs": []},
        ]
        result = {
            "dead_blocks": [{"addr": 0x3200, "size": 16, "reason": "unreachable"}],
            "patches": [{"address": 0x3200, "action": "nop_fill", "bytes": "90" * 16}],
        }
        _apply_pass_effects(blocks, "dce", result)
        addrs = [b["addr"] for b in blocks]
        assert 0x3200 not in addrs
        assert len(blocks) == 2

    def test_dce_cleans_successor_lists(self):
        blocks = [
            {"addr": 0x4000, "succs": [0x4100, 0x4200]},
            {"addr": 0x4100, "succs": []},
            {"addr": 0x4200, "succs": []},
        ]
        result = {
            "dead_blocks": [{"addr": 0x4200, "size": 8, "reason": "unreachable"}],
            "patches": [],
        }
        _apply_pass_effects(blocks, "dce", result)
        assert blocks[0]["succs"] == [0x4100]

    def test_unknown_pass_is_noop(self):
        blocks = [{"addr": 0x5000, "succs": []}]
        original = [dict(b) for b in blocks]
        _apply_pass_effects(blocks, "unknown_pass", {"patches": []})
        assert blocks == original
