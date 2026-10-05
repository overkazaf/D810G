import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.interactive import InteractiveEditor


class TestInteractiveEditor:

    def setup_method(self):
        self.editor = InteractiveEditor()

    def test_rules_loaded(self):
        assert len(self.editor.rules) >= 60

    def test_cmd_test_match(self, capsys):
        self.editor.cmd_test("(x | y) - (x & y)")
        captured = capsys.readouterr()
        assert "mba_xor_1" in captured.out or "^" in captured.out

    def test_cmd_test_no_match(self, capsys):
        # Clear all rules so nothing can match
        editor = InteractiveEditor.__new__(InteractiveEditor)
        editor.rules = []
        editor.custom_rules = []
        editor.stats = {"tested": 0, "simplified": 0, "verified": 0, "failed": 0}
        editor.cmd_test("x + y")
        captured = capsys.readouterr()
        assert "No rules matched" in captured.out

    def test_cmd_verify_equivalent(self, capsys):
        self.editor.cmd_verify("(x | y) - (x & y) = x ^ y")
        captured = capsys.readouterr()
        assert "EQUIVALENT" in captured.out

    def test_cmd_verify_not_equivalent(self, capsys):
        self.editor.cmd_verify("(x | y) - (x & y) = x + y")
        captured = capsys.readouterr()
        assert "NOT EQUIVALENT" in captured.out

    def test_cmd_add_rule(self, capsys):
        self.editor.cmd_add("test_rule (x | y) ^ (x & y) = x ^ y")
        captured = capsys.readouterr()
        assert "Added rule" in captured.out
        assert len(self.editor.custom_rules) == 1

    def test_cmd_remove_rule(self, capsys):
        from d810g_engine.mba.rules import Rule
        self.editor.custom_rules.append(
            Rule(
                id="test_r", pattern="x", replacement="x",
                commutative=False, description=""
            )
        )
        self.editor.cmd_remove("test_r")
        captured = capsys.readouterr()
        assert "Removed" in captured.out
        assert len(self.editor.custom_rules) == 0

    def test_cmd_list(self, capsys):
        self.editor.cmd_list()
        captured = capsys.readouterr()
        assert "Total:" in captured.out

    def test_cmd_stats(self, capsys):
        self.editor.cmd_stats()
        captured = capsys.readouterr()
        assert "Session Statistics" in captured.out

    def test_cmd_save_and_load(self, tmp_path, capsys):
        from d810g_engine.mba.rules import Rule
        self.editor.custom_rules.append(
            Rule(id="save_test", pattern="x ^ 0", replacement="x",
                 commutative=False, description="test")
        )
        save_path = tmp_path / "test_rules.json"
        # Monkey-patch RULES_DIR for test
        import d810g_engine.interactive as mod
        original_dir = mod.RULES_DIR
        mod.RULES_DIR = tmp_path
        try:
            self.editor.cmd_save("test_rules.json")
            captured = capsys.readouterr()
            assert "Saved 1 rules" in captured.out
            assert save_path.exists()

            before_count = len(self.editor.rules)
            self.editor.cmd_load("test_rules.json")
            assert len(self.editor.rules) == before_count + 1
        finally:
            mod.RULES_DIR = original_dir
