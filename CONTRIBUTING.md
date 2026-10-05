# Contributing to D810G

Thank you for your interest in D810G! This guide explains how to contribute.

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/D810G.git
cd D810G
```

2. Set up Python environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install z3-solver pytest
```

3. Run tests:
```bash
PYTHONPATH=python python -m pytest test/ -v
```

## Adding MBA Rules

The easiest way to contribute is adding new MBA simplification rules:

1. Create or edit a JSON file in `data/rules/`
2. Each rule needs: `id`, `pattern`, `replacement`, `commutative`, `description`
3. Add a Z3 verification test in `test/test_mba_extended.py`
4. The CI will verify rule correctness automatically

Example rule:
```json
{
    "id": "my_rule_1",
    "pattern": "(x | y) ^ (x & y)",
    "replacement": "x ^ y",
    "commutative": true,
    "description": "XOR via OR XOR AND"
}
```

Verify with CLI:
```bash
python -m d810g_engine cli simplify "(x | y) ^ (x & y)"
```

## Adding Obfuscator Support

To add support for a new obfuscator's CFF variant:

1. Create `python/d810g_engine/deflattener/your_obfuscator.py`
2. Implement `detect_pattern()` and `deflat()` functions
3. Register the handler in `deflattener/__init__.py`
4. Add tests in `test/test_your_obfuscator.py`

## Code Style

- Python: Follow PEP 8, type hints encouraged
- Java: Follow Ghidra's coding conventions
- Tests: One test per behavior, descriptive names

## Pull Requests

1. Fork the repo and create a feature branch
2. Add tests for new functionality
3. Make sure all tests pass: `python -m pytest test/ -v`
4. Submit a PR with a clear description
