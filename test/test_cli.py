import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.cli import main


def test_simplify(capsys):
    main(["simplify", "(x | y) - (x & y)"])
    captured = capsys.readouterr()
    assert "^" in captured.out
    assert "mba_xor_1" in captured.out


def test_simplify_no_match(capsys):
    main(["simplify", "x + y"])
    captured = capsys.readouterr()
    assert "no simplification" in captured.out


def test_simplify_json(capsys):
    main(["simplify", "--json", "(x | y) - (x & y)"])
    captured = capsys.readouterr()
    import json
    data = json.loads(captured.out)
    assert data["rule_id"] == "mba_xor_1"


def test_opaque_always_true(capsys):
    main(["opaque", "x == x"])
    captured = capsys.readouterr()
    assert "ALWAYS TRUE" in captured.out


def test_opaque_always_false(capsys):
    main(["opaque", "(x & 1) == 2"])
    captured = capsys.readouterr()
    assert "ALWAYS FALSE" in captured.out


def test_opaque_dynamic(capsys):
    main(["opaque", "x > 5"])
    captured = capsys.readouterr()
    assert "DYNAMIC" in captured.out


def test_rules_list(capsys):
    main(["rules"])
    captured = capsys.readouterr()
    assert "mba_basic.json" in captured.out
    assert "Total:" in captured.out
