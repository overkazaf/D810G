<div align="center">

![Stars](https://img.shields.io/github/stars/overkazaf/D810G?style=flat-square&color=58a6ff)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Ghidra](https://img.shields.io/badge/Ghidra-Plugin-bf360c?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-201-4caf50?style=flat-square)
![MBA Rules](https://img.shields.io/badge/MBA_Rules-60-58a6ff?style=flat-square)
![License](https://img.shields.io/github/license/overkazaf/D810G?style=flat-square&color=58a6ff)

</div>

# D810G

**English** | [中文](README_CN.md)

**Deobfuscation framework for Ghidra** — the most comprehensive open-source deobfuscation toolkit for the Ghidra reverse engineering platform.

D810G brings [D-810](https://gitlab.com/eshard/d810)-level deobfuscation capabilities to Ghidra. It uses a hybrid Java + Python architecture: a Ghidra plugin handles UI and binary patching, while a Python engine powered by Z3, Unicorn, Capstone, and Keystone performs the heavy analysis.

![Tests](https://img.shields.io/badge/tests-201%20passed-brightgreen)
![Rules](https://img.shields.io/badge/MBA%20rules-60-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Ghidra](https://img.shields.io/badge/Ghidra-11.x-green)
![Python](https://img.shields.io/badge/python-3.11%2B-yellow)
![Arch](https://img.shields.io/badge/arch-x86__64%20%7C%20ARM64%20%7C%20ARM32-orange)

---

## Key Features

| Module | Description |
|--------|-------------|
| **Control Flow Deflattening** | OLLVM + Tigress CFF recovery via Unicorn emulation |
| **MBA Simplification** | 60 rules with multi-pass iterative simplification and Z3 verification |
| **Opaque Predicate Elimination** | Standard + advanced (number theory, integer arithmetic) |
| **Bogus Control Flow Removal** | Detect and strip fake branches guarded by opaque predicates |
| **Dead Code Elimination** | BFS reachability analysis + NOP patching |
| **String Decryption** | XOR, multi-byte XOR, RC4, substitution table, ROT-N |
| **VM Devirtualization** | Tigress VM dispatcher detection, handler classification, bytecode tracing |
| **Full Pipeline** | 6-pass auto-chaining with fixpoint iteration |
| **Standalone CLI** | Use without Ghidra: `simplify`, `opaque`, `interactive`, `pipeline` |
| **Ghidra Analyzer** | One-click automatic deobfuscation during analysis |

---

## Quick Start (CLI — no Ghidra needed)

```bash
git clone https://github.com/overkazaf/D810G.git
cd D810G
python3 -m venv .venv && source .venv/bin/activate
pip install z3-solver unicorn keystone-engine capstone
```

### MBA Simplification

```
$ PYTHONPATH=python python -m d810g_engine cli simplify "(x | y) - (x & y)"
  (x | y) - (x & y)
  → (x ^ y) (Z3 verified)
  Rule: mba_xor_1
```

<p align="center">
  <img src="docs/assets/recordings/mba.svg" alt="MBA Simplification Demo" width="800">
</p>

### Multi-Pass Deep Simplification

```
$ PYTHONPATH=python python -m d810g_engine cli simplify --deep \
    "((x | y) - (x & y)) ^ ((x | y) - (x & y))"
  ((x | y) - (x & y)) ^ ((x | y) - (x & y))
  → ((x ^ y) ^ ((x | y) - (x & y)))  (step 1, mba_xor_1)
  → ((x ^ y) ^ (x ^ y))              (step 2, mba_xor_1)
  → 0                                 (step 3, mba_zero_1)
  Final: Z3 verified equivalent
  Iterations: 3, fixpoint: True
```

<p align="center">
  <img src="docs/assets/recordings/deep_mba.svg" alt="Deep MBA Simplification Demo" width="800">
</p>

### Opaque Predicate Detection

```
$ PYTHONPATH=python python -m d810g_engine cli opaque "x == x"
  x == x
  → ALWAYS TRUE  — opaque, can be eliminated

$ PYTHONPATH=python python -m d810g_engine cli opaque "(x & 1) == 2"
  (x & 1) == 2
  → ALWAYS FALSE — opaque, can be eliminated

$ PYTHONPATH=python python -m d810g_engine cli opaque "x > 5"
  x > 5
  → DYNAMIC      — real condition, keep as-is
```

<p align="center">
  <img src="docs/assets/recordings/opaque.svg" alt="Opaque Predicate Detection Demo" width="800">
</p>

### Interactive Rule Editor

```
$ PYTHONPATH=python python -m d810g_engine cli interactive
  D810G Interactive Rule Editor
  Loaded 60 rules from 4 files

d810g> test (x | y) - (x & y)
  → (x ^ y)  [Z3 verified]
     Rule: mba_xor_1

d810g> verify (x & y) + (x ^ y) = x | y
  8-bit:  EQUIVALENT
  16-bit: EQUIVALENT
  32-bit: EQUIVALENT
  64-bit: EQUIVALENT

d810g> add my_rule ~(~x & ~y) = x | y
  Added rule 'my_rule': ~(~x & ~y) -> x | y [verified]
```

### All CLI Commands

```bash
PYTHONPATH=python python -m d810g_engine cli simplify "<expr>"      # one-shot simplify
PYTHONPATH=python python -m d810g_engine cli simplify --deep "<expr>" # multi-pass
PYTHONPATH=python python -m d810g_engine cli opaque "<condition>"    # classify predicate
PYTHONPATH=python python -m d810g_engine cli rules                   # list all 60 rules
PYTHONPATH=python python -m d810g_engine cli rules --verify          # Z3-verify all rules
PYTHONPATH=python python -m d810g_engine cli batch < exprs.txt       # batch simplify
PYTHONPATH=python python -m d810g_engine cli interactive             # REPL mode
PYTHONPATH=python python -m d810g_engine cli pipeline input.json     # full pipeline
```

---

## Demo Scripts

D810G ships with 8 interactive demo scripts showcasing every module. Run them all at once or individually:

```bash
# Run all demos
PYTHONPATH=python python demo/demo_all.py

# Or run individually
PYTHONPATH=python python demo/demo_mba.py         # MBA simplification (7 examples + Z3 proof table)
PYTHONPATH=python python demo/demo_deep_mba.py     # Multi-pass iterative simplification
PYTHONPATH=python python demo/demo_opaque.py       # Opaque predicate detection (always_true/false/dynamic)
PYTHONPATH=python python demo/demo_bcf.py          # Bogus control flow removal (3-layer BCF + ASCII diagrams)
PYTHONPATH=python python demo/demo_deflat.py       # Control flow deflattening (OLLVM state machine)
PYTHONPATH=python python demo/demo_strings.py      # String decryption (XOR / RC4 / multi-byte / ROT-N)
PYTHONPATH=python python demo/demo_vm.py           # VM devirtualization (handler table + Fibonacci pseudocode)
PYTHONPATH=python python demo/demo_pipeline.py     # Full 6-pass pipeline with fixpoint iteration
```

---

## Ghidra Integration

### Plugin (Manual)

1. Build the extension (see [Building from Source](#building-from-source))
2. In Ghidra: **File > Install Extensions > Add extension** (select the zip)
3. Right-click any function → **D810G > Deobfuscate Function**
4. Results appear in the **D810G Results** panel

### Analyzer (Automatic)

D810G includes a Ghidra `Analyzer` that automatically detects and deobfuscates functions during analysis:

1. Open **Analysis > Auto Analyze** options
2. Enable **D810G Deobfuscation**
3. Run analysis — D810G scans all functions for obfuscation patterns and deobfuscates suspicious ones

### Headless Script

```bash
analyzeHeadless /path/to/project Project -import binary.exe \
    -postScript headless_deobfuscate.py
```

### Screenshots

<p align="center">
  <img src="docs/assets/mockups/ghidra_comparison.svg" alt="Before and After D810G Deobfuscation" width="1000">
</p>

<details>
<summary>More screenshots</summary>

**Obfuscated code (before):**

<p align="center">
  <img src="docs/assets/mockups/ghidra_before.svg" alt="Ghidra showing OLLVM-obfuscated code" width="800">
</p>

**Right-click to deobfuscate:**

<p align="center">
  <img src="docs/assets/mockups/ghidra_rightclick.svg" alt="D810G right-click context menu" width="800">
</p>

**Clean code (after):**

<p align="center">
  <img src="docs/assets/mockups/ghidra_after.svg" alt="Ghidra showing deobfuscated code with D810G results" width="800">
</p>

</details>

---

## Architecture

![Architecture](docs/assets/architecture.svg)

### Deobfuscation Pipeline

The full pipeline runs 6 passes in optimal order, iterating until no more changes:

![Pipeline](docs/assets/pipeline.svg)

---

## Supported Obfuscation

| Technique | Status | Details |
|---|---|---|
| OLLVM Control Flow Flattening | ✅ | Switch-dispatch + Unicorn emulation + Keystone patching |
| Tigress CFF (indirect jump) | ✅ | Jump table detection and resolution |
| Tigress CFF (if-chain) | ✅ | Sequential comparison chain detection |
| OLLVM Bogus Control Flow | ✅ | Opaque predicate-guarded fake branch removal |
| MBA Expressions | ✅ | 60 rules, multi-pass iterative, sub-expression recursive |
| Opaque Predicates (standard) | ✅ | Z3 bitvector satisfiability analysis |
| Opaque Predicates (advanced) | ✅ | Integer arithmetic fallback + number theory patterns |
| Dead Code Elimination | ✅ | BFS reachability + NOP fill (x86/ARM64/ARM32) |
| String Encryption (XOR) | ✅ | Single-byte, multi-byte, XOR-with-index |
| String Encryption (RC4) | ✅ | Brute-force key search |
| String Encryption (substitution) | ✅ | ROT-N and custom lookup tables |
| Tigress VM (detection) | ✅ | Dispatcher detection + handler classification |
| Tigress VM (bytecode tracing) | ✅ | Execution simulation + pseudocode generation |
| Full Pipeline | ✅ | 6-pass auto-chain with fixpoint iteration |
| Standalone CLI | ✅ | simplify, opaque, rules, batch, interactive, pipeline |
| Ghidra Analyzer | ✅ | Automatic analysis integration |
| Ghidra Headless | ✅ | Batch scan via `analyzeHeadless` |

### Architecture Support

| Architecture | Deflattening | Patching | Dead Code |
|---|---|---|---|
| x86_64 | ✅ | ✅ | ✅ |
| ARM64 (AArch64) | ✅ | ✅ | ✅ |
| ARM32 | ✅ | ✅ | ✅ |

---

## MBA Rule Sets

D810G ships with **60 rules** across 4 rule files:

| Rule Set | Count | Description |
|---|---|---|
| `mba_basic.json` | 10 | Fundamental MBA identities (XOR, AND, OR equivalences) |
| `mba_hackers_delight.json` | 25 | Bit manipulation from Hacker's Delight (abs, min, max, De Morgan) |
| `mba_ollvm.json` | 15 | OLLVM instruction substitution patterns |
| `mba_constant_folding.json` | 10 | Algebraic identities and constant folding |

### Adding Custom Rules

Create a JSON file in `data/rules/`:

```json
{
  "name": "my_rules",
  "description": "Custom MBA rules",
  "rules": [
    {
      "id": "my_xor_1",
      "pattern": "(x | y) ^ (x & y)",
      "replacement": "x ^ y",
      "commutative": true,
      "description": "XOR via OR XOR AND"
    }
  ]
}
```

Or use the interactive editor:
```bash
PYTHONPATH=python python -m d810g_engine cli interactive
d810g> add my_rule (x | y) ^ (x & y) = x ^ y
d810g> save my_rules.json
```

---

## Installation

### Option 1: CLI Only (no Ghidra)

```bash
git clone https://github.com/overkazaf/D810G.git
cd D810G
python3 -m venv .venv && source .venv/bin/activate
pip install z3-solver unicorn keystone-engine capstone
```

### Option 2: Ghidra Extension

```bash
# Build
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x
cd D810G
$GHIDRA_INSTALL_DIR/support/gradle/gradlew buildExtension

# Install
# In Ghidra: File > Install Extensions > select dist/*.zip
# Set up venv in the extension directory:
cd <ghidra_extensions>/D810G
python3 -m venv .venv && source .venv/bin/activate
pip install z3-solver unicorn keystone-engine capstone
```

---

## Building from Source

### Requirements

- JDK 17+
- Ghidra 11.x
- Python 3.11+
- `pip install z3-solver unicorn keystone-engine capstone pytest`

### Build & Test

```bash
# Build Ghidra extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra
$GHIDRA_INSTALL_DIR/support/gradle/gradlew buildExtension

# Run all 201 tests
source .venv/bin/activate
PYTHONPATH=python python -m pytest test/ -v
```

<p align="center">
  <img src="docs/assets/recordings/tests.svg" alt="Test Suite Demo" width="800">
</p>

### Test Modules

```bash
python -m pytest test/test_deflattener.py     # CFF + Unicorn emulation (12 tests)
python -m pytest test/test_tigress.py         # Tigress variants (6 tests)
python -m pytest test/test_mba.py             # MBA matching (9 tests)
python -m pytest test/test_mba_extended.py    # 60-rule Z3 verification (41 tests)
python -m pytest test/test_mba_deep.py        # Multi-pass simplification (8 tests)
python -m pytest test/test_opaque.py          # Opaque predicates (6 tests)
python -m pytest test/test_opaque_advanced.py # Advanced predicates (11 tests)
python -m pytest test/test_bcf.py             # Bogus control flow (10 tests)
python -m pytest test/test_dce.py             # Dead code elimination (14 tests)
python -m pytest test/test_strings.py         # String decryption (19 tests)
python -m pytest test/test_virtualization.py  # VM analysis (13 tests)
python -m pytest test/test_vm_tracer.py       # Bytecode tracing (13 tests)
python -m pytest test/test_pipeline.py        # Full pipeline (9 tests)
python -m pytest test/test_cli.py             # CLI commands (7 tests)
python -m pytest test/test_interactive.py     # Interactive editor (10 tests)
python -m pytest test/test_protocol.py        # IPC protocol (4 tests)
python -m pytest test/test_integration.py     # Integration (9 tests)
```

---

## Project Structure

```
D810G/
├── src/main/java/d810g/         # Ghidra plugin (Java)
│   ├── D810GPlugin.java         # Plugin entry point
│   ├── D810GAnalyzer.java       # Auto-analysis integration
│   ├── engine/                  # Python process management + JSON-RPC
│   ├── core/                    # Orchestrator, PatchManager, PcodeUtils
│   ├── actions/                 # Right-click menu actions
│   └── ui/                      # Results panel
├── python/d810g_engine/         # Analysis engine (Python)
│   ├── server.py                # JSON-RPC server
│   ├── cli.py                   # Standalone CLI
│   ├── interactive.py           # Interactive rule editor
│   ├── deflattener/             # OLLVM + Tigress + Unicorn
│   ├── mba/                     # Rules + matcher + Z3 verifier
│   ├── opaque/                  # Standard + advanced predicates
│   ├── bcf/                     # Bogus control flow
│   ├── dce/                     # Dead code elimination
│   ├── strings/                 # String decryption (XOR/RC4/sub)
│   ├── virtualization/          # VM analysis + bytecode tracer
│   └── pipeline/                # Multi-pass orchestrator
├── data/rules/                  # MBA rule definitions (60 rules)
├── test/                        # 201 tests
├── demo/                        # Demo scripts
├── scripts/                     # Headless analysis scripts
└── .github/workflows/           # CI (Python 3.11/3.12/3.13)
```

---

## Credits

D810G is inspired by:
- [D-810](https://gitlab.com/eshard/d810) — the original IDA Pro deobfuscation plugin by eShard
- [D-810-ng](https://github.com/nickcano/D-810-ng) — community fork with updates

Built to bring these capabilities — and more — to the Ghidra reverse engineering ecosystem.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
