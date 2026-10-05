import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.pipeline.orchestrator import (
    PipelinePass, PipelineResult, build_pipeline, run_pipeline,
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

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.pipeline import register_handlers
        server = Server()
        register_handlers(server)
        assert "pipeline.run" in server._handlers
