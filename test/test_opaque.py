import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.opaque.predicate import classify_predicate


def test_always_true_unsigned():
    """x*x >= 0 is always true for unsigned bitvectors."""
    result = classify_predicate("(x * x) >= 0", bit_width=32, signed=False)
    assert result["classification"] == "always_true"


def test_always_false():
    """(x & 1) == 2 is always false -- x&1 can only be 0 or 1."""
    result = classify_predicate("(x & 1) == 2", bit_width=32)
    assert result["classification"] == "always_false"


def test_dynamic():
    """x > 5 depends on x -- should be dynamic."""
    result = classify_predicate("x > 5", bit_width=32)
    assert result["classification"] == "dynamic"


def test_always_true_identity():
    """x == x is always true."""
    result = classify_predicate("x == x", bit_width=32)
    assert result["classification"] == "always_true"


def test_always_false_contradiction():
    """(x & 3) == 4 is always false -- x&3 is at most 3."""
    result = classify_predicate("(x & 3) == 4", bit_width=32)
    assert result["classification"] == "always_false"


def test_eliminate_predicates_api():
    from d810g_engine.opaque import eliminate_predicates
    result = eliminate_predicates({
        "predicates": [
            {"expression": "x == x", "address": 0x1000, "bit_width": 32},
            {"expression": "(x & 1) == 2", "address": 0x1010, "bit_width": 32},
            {"expression": "x > 5", "address": 0x1020, "bit_width": 32},
        ]
    })
    assert len(result["results"]) == 3
    assert len(result["patches"]) == 2  # only always_true and always_false get patches
    actions = {p["address"]: p["action"] for p in result["patches"]}
    assert actions[0x1000] == "force_true"
    assert actions[0x1010] == "force_false"
