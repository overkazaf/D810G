# D810G

**Deobfuscation framework for Ghidra** -- control flow deflattening, MBA simplification, and opaque predicate elimination.

D810G brings the deobfuscation capabilities of [D-810](https://gitlab.com/eshard/d810) to the Ghidra ecosystem. It uses a hybrid Java + Python architecture: a Ghidra plugin extracts P-Code and binary data, sends it to a Python analysis engine over JSON-RPC, and applies the resulting patches back into the program.

![Tests](https://img.shields.io/badge/tests-92%20passed-brightgreen)
![Rules](https://img.shields.io/badge/MBA%20rules-60-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Ghidra](https://img.shields.io/badge/Ghidra-11.x-green)
![Python](https://img.shields.io/badge/python-3.11%2B-yellow)

---

## Features

### Control Flow Deflattening
Recovers the original control flow from OLLVM and Tigress flattened functions. Detects dispatcher patterns (switch-dispatch, indirect jump tables, if-chains), uses **Unicorn** emulation to trace state variable transitions, and generates binary patches with **Keystone** to restore direct jumps. Supports x86_64 and ARM64.

### MBA Expression Simplification
Simplifies Mixed Boolean-Arithmetic expressions using **60 rewrite rules** across 4 rule sets (basic, Hacker's Delight, OLLVM-specific, constant folding). Every rule is formally verified with **Z3** to guarantee semantic equivalence. Rules are defined in JSON and can be extended without code changes.

### Opaque Predicate Elimination
Detects and removes opaque predicates (always-true / always-false branch conditions) using Z3 satisfiability analysis. Batch-classifies all conditional branches in a function, patches dead branches with unconditional jumps or NOPs.

### Standalone CLI
Use D810G without Ghidra for quick analysis:

```bash
# Simplify an MBA expression
python -m d810g_engine cli simplify "(x | y) - (x & y)"
#   (x | y) - (x & y) → (x ^ y)  (Z3 verified)

# Classify an opaque predicate
python -m d810g_engine cli opaque "(x & 1) == 2"
#   → ALWAYS FALSE — opaque, can be eliminated

# List all 60 rules
python -m d810g_engine cli rules

# Batch simplify from file
python -m d810g_engine cli batch < expressions.txt
```

### Ghidra Headless Script
Batch-scan binaries for obfuscated functions without the GUI:

```bash
analyzeHeadless /path/to/project Project -import binary.exe \
    -postScript headless_deobfuscate.py
```

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
| OLLVM Control Flow Flattening | **Supported** | Switch-dispatch detection + Unicorn emulation + Keystone patching |
| Tigress CFF (indirect jump) | **Supported** | Jump table detection and resolution |
| Tigress CFF (if-chain) | **Supported** | Sequential comparison chain detection |
| MBA Expressions | **Supported** | 60 rules (basic + Hacker's Delight + OLLVM + constant folding), Z3-verified |
| Opaque Predicates | **Supported** | Z3 satisfiability analysis, batch classification |
| Standalone CLI | **Supported** | `simplify`, `opaque`, `rules`, `batch` commands |
| Headless Batch Scan | **Supported** | Ghidra `analyzeHeadless` integration |
| OLLVM Bogus Control Flow | Planned | |
| OLLVM String Encryption | Planned | |
| Tigress Virtualization | Planned | |

---

## Adding Custom Rules

MBA simplification rules are defined in JSON files under `data/rules/`. D810G ships with 4 rule sets (60 rules total):

- `mba_basic.json` -- 10 fundamental identities
- `mba_hackers_delight.json` -- 25 bit-manipulation identities from Hacker's Delight
- `mba_ollvm.json` -- 15 OLLVM instruction substitution patterns
- `mba_constant_folding.json` -- 10 algebraic identity / constant folding rules

Each rule specifies a pattern and its simplified replacement:

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
- z3-solver, unicorn, keystone-engine, capstone (`pip install z3-solver unicorn keystone-engine capstone`)

### Build

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x

cd D810G
gradle buildExtension
```

The extension zip will be created in `dist/`.

---

## Running Tests

92 tests covering protocol, deflattening (OLLVM + Tigress), MBA (basic + extended), opaque predicates, CLI, and integration.

```bash
cd D810G
source .venv/bin/activate

# Run all 92 tests
PYTHONPATH=python python -m pytest test/ -v

# Run specific modules
python -m pytest test/test_deflattener.py -v    # CFF detection + Unicorn emulation
python -m pytest test/test_mba.py -v            # MBA matching + Z3 verification
python -m pytest test/test_mba_extended.py -v   # 60-rule Z3 verification
python -m pytest test/test_opaque.py -v         # Opaque predicate classification
python -m pytest test/test_tigress.py -v        # Tigress variant detection
python -m pytest test/test_cli.py -v            # CLI commands
```

---

## Roadmap

- [x] ~~**Tigress CFF support**~~ -- indirect jump table + if-chain detection
- [x] ~~**Unicorn symbolic execution**~~ -- real emulation-based state recovery
- [x] ~~**Hacker's Delight rules**~~ -- 25 bit-manipulation identities
- [x] ~~**Standalone CLI**~~ -- use without Ghidra
- [x] ~~**Headless batch scan**~~ -- `analyzeHeadless` integration
- [ ] **Ghidra Analyzer integration** -- run as a one-click auto-analysis step
- [ ] **OLLVM Bogus Control Flow** -- detect and strip bogus conditional branches
- [ ] **String decryption** -- recover OLLVM-encrypted string literals
- [ ] **Tigress Virtualization** -- handle bytecode-based obfuscation
- [ ] **Interactive rule editor** -- GUI for creating and testing MBA rules

---

## Credits

D810G is inspired by:
- [D-810](https://gitlab.com/eshard/d810) -- the original IDA Pro deobfuscation plugin by eShard
- [D-810-ng](https://github.com/nickcano/D-810-ng) -- community fork with updates

Built to bring the same capabilities to the Ghidra reverse engineering ecosystem.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
