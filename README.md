# D810G

**Deobfuscation framework for Ghidra** -- control flow deflattening, MBA simplification, and opaque predicate elimination.

D810G brings the deobfuscation capabilities of [D-810](https://gitlab.com/eshard/d810) to the Ghidra ecosystem. It uses a hybrid Java + Python architecture: a Ghidra plugin extracts P-Code and binary data, sends it to a Python analysis engine over JSON-RPC, and applies the resulting patches back into the program.

<!-- badges -->
<!-- ![Build](https://img.shields.io/github/actions/workflow/status/YOUR_ORG/D810G/build.yml?branch=main) -->
<!-- ![License](https://img.shields.io/badge/license-Apache%202.0-blue) -->
<!-- ![Ghidra](https://img.shields.io/badge/Ghidra-11.x-green) -->

---

## Features

### Control Flow Deflattening
Recovers the original control flow from OLLVM-style switch-dispatch flattened functions. Detects the dispatcher pattern, identifies relevant blocks, and uses symbolic execution with Z3 to resolve successor relationships.

### MBA Expression Simplification
Simplifies Mixed Boolean-Arithmetic expressions using a rule-based engine with 10+ rewrite rules. Every rule is formally verified with Z3 to guarantee semantic equivalence. Rules are defined in JSON and can be extended without code changes.

### Opaque Predicate Elimination
Detects and removes opaque predicates (always-true / always-false branch conditions) using Z3 satisfiability analysis. Patches dead branches with unconditional jumps or NOPs.

---

## Installation

### 1. Install the Ghidra Extension

```bash
# Build from source (see "Building from Source" below), then:
# In Ghidra: File > Install Extensions > Add extension (select the zip)
```

Or download a release zip from the Releases page and install it through Ghidra's extension manager.

### 2. Set Up the Python Engine

The Python engine requires Python 3.12+ and z3-solver.

```bash
cd <ghidra_extensions>/D810G

# Create a virtualenv (D810G looks for .venv/ automatically)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install z3-solver
```

---

## Usage

1. Open a binary in Ghidra and run the auto-analysis.
2. Navigate to an obfuscated function.
3. Right-click in the Listing view and select **D810G > Deobfuscate Function**.
4. The plugin starts the Python engine (if not already running), sends the function data for analysis, and applies patches.
5. Check the **D810G Results** panel for logs and status.

The results panel shows per-function summaries including the number of patches applied, detected obfuscation types, and any errors.

---

## Architecture

```
+-----------------+       JSON-RPC (stdio)       +-------------------+
|   Ghidra Plugin |  <========================>  |   Python Engine   |
|   (Java)        |   Content-Length framing      |   (d810g_engine)  |
+-----------------+                               +-------------------+
| D810GPlugin     |                               | server.py         |
| EngineManager   |--- start/stop subprocess ---->| protocol.py       |
| EngineProtocol  |--- send(method, params) ----->|                   |
| PcodeUtils      |   extract blocks & bytes      | deflattener/      |
| PatchManager    |   apply returned patches      |   detector.py     |
| Orchestrator    |   coordinate passes           |   ollvm.py        |
| DeobfuscateFunc |   context menu action         |   symbolic.py     |
| D810GProvider   |   results UI panel            | mba/              |
+-----------------+                               |   rules.py        |
                                                  |   matcher.py      |
                                                  |   verifier.py     |
                                                  | opaque/           |
                                                  |   predicate.py    |
                                                  +-------------------+
```

**Pipeline per function:**

1. Java side extracts P-Code basic blocks and raw bytes from the function.
2. Sends a `deflat.run` request to the Python engine with block graph, binary hex, arch, and base address.
3. Python engine runs deflattening (pre-processing) to recover control flow.
4. MBA simplification and opaque predicate elimination run as post-processing.
5. Engine returns a list of binary patches (address + bytes).
6. Java side applies patches to the Ghidra program via `PatchManager`.

---

## Supported Obfuscation

| Technique | Status | Notes |
|---|---|---|
| OLLVM Control Flow Flattening | Supported | Switch-dispatch pattern detection + symbolic recovery |
| MBA Expressions | Supported | 10 built-in rules, Z3-verified, extensible via JSON |
| Opaque Predicates | Supported | Z3 satisfiability analysis, NOP/JMP patching |
| OLLVM Bogus Control Flow | Planned | |
| OLLVM String Encryption | Planned | |
| Tigress Virtualization | Planned | |
| Instruction Substitution | Planned | |

---

## Adding Custom Rules

MBA simplification rules are defined in `data/rules/mba_basic.json`. Each rule specifies a pattern and its simplified replacement:

```json
{
  "id": "my_custom_rule",
  "pattern": "(x | y) - (x & y)",
  "replacement": "x ^ y",
  "commutative": true,
  "description": "XOR via OR minus AND"
}
```

Fields:
- **`pattern`** -- the MBA expression to match (using variables `x`, `y`)
- **`replacement`** -- the simplified equivalent
- **`commutative`** -- if `true`, also matches with operands swapped
- **`description`** -- human-readable explanation

All rules are automatically verified with Z3 at load time. If a rule is not semantically equivalent, it will be rejected with a warning.

To add rules, either append to `mba_basic.json` or create a new JSON file in `data/rules/` following the same schema.

---

## Building from Source

### Requirements

- JDK 17+
- Ghidra 11.x (set `GHIDRA_INSTALL_DIR`)
- Python 3.12+
- z3-solver (`pip install z3-solver`)

### Build

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x

cd D810G
gradle buildExtension
```

The extension zip will be created in `dist/`.

---

## Running Tests

The Python engine has a full test suite covering protocol, deflattening, MBA, and opaque predicate modules.

```bash
cd D810G

# Activate the virtualenv
source .venv/bin/activate

# Run all tests
pytest test/ -v

# Run specific test modules
pytest test/test_protocol.py -v
pytest test/test_deflattener.py -v
pytest test/test_mba.py -v
pytest test/test_opaque.py -v
```

---

## Roadmap

- [ ] **Tigress support** -- handle virtualization-based obfuscation
- [ ] **Full symbolic execution** -- extend Z3-backed analysis to cover more flattening variants
- [ ] **Ghidra Analyzer integration** -- run as a one-click auto-analysis step
- [ ] **Hacker's Delight rules** -- additional MBA rules from bit-manipulation identities
- [ ] **OLLVM Bogus Control Flow** -- detect and strip bogus conditional branches
- [ ] **String decryption** -- recover OLLVM-encrypted string literals
- [ ] **Batch mode** -- deobfuscate all functions in a binary at once

---

## Credits

D810G is inspired by:
- [D-810](https://gitlab.com/eshard/d810) -- the original IDA Pro deobfuscation plugin by eShard
- [D-810-ng](https://github.com/nickcano/D-810-ng) -- community fork with updates

Built to bring the same capabilities to the Ghidra reverse engineering ecosystem.

---

## License

Apache License 2.0. See [Module.manifest](Module.manifest) for details.
