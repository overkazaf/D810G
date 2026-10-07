# D810G: Roadmap to 9/10

## Current Score: 7/10

**Evidence for 7/10:** 398 tests all passing, 96 Z3-verified MBA rules with 0 duplicates,
7-pass pipeline with state propagation + patch dedup, shared parser, string decryption with
bigram + code-pattern scoring, VM handler classification via Capstone, Java CI with Ghidra
build, 12 realistic binary test cases, round 2 bugs fixed. All 7 demos run cleanly. Pipeline
converges correctly on cyclic blocks and survives invalid expressions without crashing.

---

## What's blocking 9/10 (ordered by impact)

### Must-fix (each adds ~0.3 to score)

#### 1. README is dangerously stale (+0.3)

The README is the first thing users see. It currently claims:
- **201 tests** (actual: 398)
- **60 MBA rules** (actual: 96)
- **4 rule files** (actual: 6 -- `mba_advanced.json` and `mba_chains.json` missing from listing)
- **6-pass pipeline** (actual: 7 -- MBA pass added)
- "Loaded 60 rules from 4 files" in interactive demo output
- Test module list shows wrong counts (e.g., "MBA matching (9 tests)" -- missing test_parser 54,
  test_mba_advanced_chains 63, test_real_binary 12, test_vm_disasm 31)
- Badges at top say "Tests-201" and "MBA_Rules-60"

**Fix:** Update every number in README.md and README_CN.md. Replace badges, feature table
("60 rules"), "Full Pipeline" row ("6-pass"), project structure ("60 rules", "201 tests"),
and test module listing. Update CONTRIBUTING.md pip install line (missing unicorn, keystone,
capstone). This is a single `sed` + manual review pass, ~30 minutes.

#### 2. MBA pass crashes on comparison expressions (+0.3)

The pipeline's MBA pass throws `Z3Exception: sort mismatch` when a block condition contains
a comparison operator (e.g., `(x | y) - (x & y) > 5`). Confirmed reproducible:

```python
simplify_expression_deep({"expression": "(x | y) - (x & y) > 5", "verify": True})
# -> Z3Exception: sort mismatch
```

The MBA matcher uses a separate AST that has no comparison ops. When the shared parser
(`eval_z3`) produces a boolean Z3 expression (from `==`, `>`, etc.) and the verifier tries
`Not(lhs == rhs)` with `lhs` being a bitvector and `rhs` a boolean, Z3 throws.

**Fix in `_mba_pass` (orchestrator.py):** Before passing a condition to `simplify_expression_deep`,
strip the comparison operator and simplify only the arithmetic sub-expression(s). If the
condition is `LHS op RHS`, simplify LHS and RHS independently, then reconstruct.
Alternative: wrap the call in try/except and skip expressions with comparison operators.
The try/except is already there in the pipeline, but the error status string is unhelpful
-- change it to log the specific expression that failed.

#### 3. No test coverage reporting (+0.3)

No `pytest-cov` in CI. Without coverage data, there is no way to know which code paths are
untested. The `requirements-dev.txt` file exists but only contains `-r requirements.txt`.

**Fix:**
1. `pip install pytest-cov` and add to `requirements-dev.txt`
2. Add `--cov=d810g_engine --cov-report=term-missing --cov-report=html` to CI pytest invocation
3. Set a target: 80% line coverage on `python/d810g_engine/`
4. Add `htmlcov/` to `.gitignore`
5. Optionally add a coverage badge via codecov.io or coveralls

---

### Should-fix (each adds ~0.1-0.2)

#### 4. 41 public functions missing docstrings (+0.2)

58% of public functions have docstrings (53/90). Missing on: `Server.__init__`, `register`,
`serve`, `encode_message`, `decode_message`, `main` (several modules), all `register_handlers`,
`load_rules`, `eliminate_predicates`, `InteractiveEditor.__init__`, etc.

**Fix:** Add one-line docstrings to all 37 missing public functions. Most are trivial
("Register analysis handlers on the server."), but load_rules and eliminate_predicates
deserve parameter docs.

#### 5. 54% type hint coverage (+0.2)

85/157 functions have full type annotations. 41 public/init functions lack either return
type or argument types. Key gaps: `cmd_simplify(args)`, `cmd_opaque(args)`, `main(argv)`,
`InteractiveEditor.cmd_*` methods, `register_handlers(server)`.

**Fix:** Add type annotations to all public functions. Most are `-> None` or `-> int`.
The argparse handler functions take `argparse.Namespace` and return `None`.

#### 6. Unused imports (+0.15)

37 detected. Real issues (not `__future__` annotations):
- `interactive.py`: unused `readline`, `sys`, `Any`, `simplify_expression`, `Op`
- `opaque/advanced.py`: unused `BitVecVal`, `And`, `ForAll`, `IntVal`, `ArithRef`, `Exists`
- `virtualization/disasm.py`: unused `CS_GRP_CALL`, `CS_GRP_RET`, `X86_INS_JMP`
- `mba/verifier.py`: unused `_re`

**Fix:** Remove all genuinely unused imports. The `from __future__ import annotations`
entries are false positives (needed for `X | Y` type syntax in 3.10/3.11). Keep `readline`
in interactive.py (side effect import for line editing). Run `ruff check --select F401`
after installing ruff.

#### 7. Only one module uses `logging` (+0.15)

Only `deflattener/symbolic.py` uses Python logging. Every other module swallows errors
silently or prints to stdout. The pipeline catches exceptions but reports them as status
strings like `"error: sort mismatch"` with no stack trace and no log destination.

**Fix:**
1. Add `log = logging.getLogger(__name__)` to every module
2. In pipeline orchestrator, `log.warning(...)` on pass errors with full traceback
3. In server.py, configure `logging.basicConfig(level=logging.INFO)` at startup
4. In CLI, add `--verbose`/`-v` flag that sets `logging.DEBUG`

#### 8. No user-configurable settings (+0.15)

Timeouts, max iterations, rule file paths, and enabled passes are all hardcoded or only
changeable via API params. There is no config file or environment variable support.

**Fix:** Create `d810g_engine/config.py` with defaults:
```python
D810G_TIMEOUT_MS = int(os.environ.get("D810G_TIMEOUT_MS", "5000"))
D810G_MAX_ITERATIONS = int(os.environ.get("D810G_MAX_ITERATIONS", "3"))
D810G_RULES_DIR = os.environ.get("D810G_RULES_DIR", "data/rules")
```
Use these in `classify_predicate`, `run_pipeline`, and `simplify_expression_deep`.

#### 9. Pipeline opaque pass doesn't generate patches for standalone predicates (+0.1)

When opaque predicates appear in blocks that are NOT BCF (no diamond-convergence pattern),
the opaque pass returns `"no_predicates"` even though the `_wrap_opaque` wrapper correctly
extracts conditions from blocks. The issue: the opaque pass generates patches of
`{"action": "force_true"}` but these don't have a `"target"` field, so the pipeline dedup
key `(addr, action, target=0)` may conflict.

Confirmed: `_wrap_opaque` extracts predicates from blocks and `eliminate_predicates` does
classify them, but the patches it produces are not in the format the pipeline expects
(no `"address"` key in the right place for BCF's `_apply_pass_effects`).

**Fix:** Ensure opaque patch format matches what `_apply_pass_effects` expects. The opaque
pass returns `results` (with addresses) and `patches` -- the `_apply_pass_effects` handler
reads from `results`, not `patches`. Verify the two are consistent and add a test.

#### 10. `requirements-dev.txt` is essentially empty (+0.1)

It just contains `-r requirements.txt`. Should include development and quality tools.

**Fix:** Add to `requirements-dev.txt`:
```
-r requirements.txt
pytest-cov>=4.0
ruff>=0.4
mypy>=1.8
```

#### 11. No CHANGELOG.md (+0.1)

No version history. Users have no way to know what changed between versions.

**Fix:** Create `CHANGELOG.md` with at least:
```
## [0.1.0] - 2026-10-07
- Initial release
- 7-pass deobfuscation pipeline (OLLVM deflat, Tigress, BCF, opaque, MBA, DCE, strings)
- 96 Z3-verified MBA rules across 6 rule files
- VM devirtualization with Capstone-based handler classification
- Standalone CLI with interactive rule editor
- Ghidra analyzer integration
- 398 tests
```

#### 12. `simplify_expression` defaults to `mba_basic.json` only (+0.1)

The single-shot `simplify_expression()` API defaults to loading only `mba_basic.json`
(7 rules). The deep version loads all 96 rules. Users calling the single-shot API miss
89 rules unless they explicitly pass each file.

**Fix:** Change the default behavior of `simplify_expression` to load all rule files,
or add a `rules="*"` / `rules="all"` sentinel that triggers loading everything from
`_RULES_DIR`. The CLI's `--rules` flag can still select a specific file.

---

## Summary of findings

| Category | Status | Detail |
|----------|--------|--------|
| Tests | All 398 pass | No failures |
| MBA rules | 96/96 match | All self-match their patterns |
| Pipeline convergence | Correct | Fixpoint reached on cyclic + all-types input |
| Error recovery | Mostly good | Pipeline survives invalid expressions, but MBA comparison crash is silent |
| Demos | All 7 run | Clean output |
| README accuracy | Stale | 12+ incorrect numbers |
| Type hints | 54% | 41 public functions missing |
| Docstrings | 58% | 37 public functions missing |
| Unused imports | 37 total | ~15 genuine (rest are `__future__` annotations) |
| Logging | 1/14 modules | Only deflattener/symbolic.py |
| Coverage | Unknown | No pytest-cov |
| Config | None | Hardcoded timeouts and paths |

## Estimated score after all fixes: 9/10

- Must-fix items 1-3: +0.9 (to 7.9)
- Should-fix items 4-12: +1.1 (to 9.0)

The remaining 1.0 to 10/10 would require: real Ghidra integration testing, benchmarks on
large binaries, plugin marketplace listing, and community validation -- things that go
beyond code quality into deployment maturity.
