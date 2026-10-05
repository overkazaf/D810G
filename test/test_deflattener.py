import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.deflattener.detector import detect_cff_pattern


def test_detect_switch_dispatch():
    """Detect OLLVM-style switch dispatcher with state variable."""
    blocks = [
        {"addr": 0x1000, "type": "dispatcher", "succs": [0x1010, 0x1020, 0x1030, 0x1040]},
        {"addr": 0x1010, "type": "case", "state_update": 0xAABBCCDD, "succs": [0x1000]},
        {"addr": 0x1020, "type": "case", "state_update": 0x11223344, "succs": [0x1000]},
        {"addr": 0x1030, "type": "case", "state_update": 0x55667788, "succs": [0x1000]},
        {"addr": 0x1040, "type": "return", "succs": []},
    ]
    result = detect_cff_pattern(blocks)
    assert result is not None
    assert result["type"] == "ollvm_switch"
    assert result["dispatcher"] == 0x1000
    assert len(result["case_blocks"]) == 3


def test_no_cff_in_normal_code():
    blocks = [
        {"addr": 0x1000, "type": "entry", "succs": [0x1010]},
        {"addr": 0x1010, "type": "block", "succs": [0x1020, 0x1030]},
        {"addr": 0x1020, "type": "block", "succs": [0x1040]},
        {"addr": 0x1030, "type": "block", "succs": [0x1040]},
        {"addr": 0x1040, "type": "return", "succs": []},
    ]
    result = detect_cff_pattern(blocks)
    assert result is None


def test_deflat_ollvm_no_cff():
    from d810g_engine.deflattener.ollvm import deflat_ollvm
    result = deflat_ollvm({
        "blocks": [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": []},
        ],
        "binary_hex": "c3",
    })
    assert result["status"] == "no_cff_detected"


def test_deflat_ollvm_with_cff():
    from d810g_engine.deflattener.ollvm import deflat_ollvm
    result = deflat_ollvm({
        "blocks": [
            {"addr": 0x1000, "succs": [0x1010, 0x1020, 0x1030, 0x1040]},
            {"addr": 0x1010, "state_update": 0xAA, "succs": [0x1000]},
            {"addr": 0x1020, "state_update": 0xBB, "succs": [0x1000]},
            {"addr": 0x1030, "state_update": 0xCC, "succs": [0x1000]},
            {"addr": 0x1040, "succs": []},
        ],
        "binary_hex": "90" * 100,
    })
    assert result["status"] == "deobfuscated"
    assert result["pattern"]["type"] == "ollvm_switch"
