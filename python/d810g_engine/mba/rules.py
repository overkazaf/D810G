"""MBA simplification rule definitions and loading."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Rule:
    """A single MBA simplification rule with pattern and replacement."""

    id: str
    pattern: str
    replacement: str
    commutative: bool
    description: str


def load_rules(path: str | Path) -> list[Rule]:
    """Load MBA rules from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    return [
        Rule(
            id=r["id"],
            pattern=r["pattern"],
            replacement=r["replacement"],
            commutative=r.get("commutative", False),
            description=r.get("description", ""),
        )
        for r in data["rules"]
    ]
