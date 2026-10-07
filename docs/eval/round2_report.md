# D810G Round 2 Evaluation Report

**Date:** 2026-10-07
**Scope:** Verify Round 1 fixes + discover new issues
**Environment:** Python 3.12.5, Z3 solver, Capstone 5.x, macOS Darwin 25.6.0
**Test suite:** 373 automated tests (all passing) + 28 manual functional tests

---

## Round 1 Fix Verification

All 5 major fixes from Round 1 are verified working.

| # | Fix | Status | Evidence |
|---|-----|--------|----------|
| 1 | Pipeline convergence + dedup | **PASS** | 2 iterations, 2 unique patches, fixpoint=True. No duplicate patches across iterations. |
| 2 | Verifier rejects bad equivalences | **PASS** | `x >> 1` vs `x` = False; `abs(x)` vs `x` = False; `(x|y)-(x&y)` vs `x^y` = True. Shift, modulo, and comparison operators all work. |
| 3 | Opaque predicate error handling | **PASS** | Empty string returns `{classification: "error"}`; non-boolean `x + y` returns `"error"`; hex `0xff`/`0x41` parsed correctly; `(x*(x+1)) % 2 == 0` classified as `always_true`. |
| 4 | String decryption false positives | **PASS** | "Hello, World!" XOR-0x42 encrypted: 4 candidates returned (was 190+). Correct key (0x42) ranked first with highest score (0.8462). |
| 5 | Shared parser consolidation | **PASS** | Parses `(x|y)-(x&y)`, `x<<1`, `(x*(x+1))%2==0`, `~(x^y)`, `0x1234+x` all correctly. Function calls, empty strings, and trailing operators all raise ValueError. |

### Additional Round 1 fixes verified:

| Fix | Status | Evidence |
|-----|--------|----------|
| Pipeline state propagation | **PASS** | BCF removal updates block successors; DCE removes dead blocks from graph; subsequent iterations see updated state. |
| Patch deduplication | **PASS** | Complex multi-BCF scenario (6 blocks, 2 opaque conditions): 4 total patches across 2 iterations, zero duplicates. |
| 108 MBA rules loaded | **PASS** | 6 rule files: basic(10) + ollvm(15) + constant_folding(10) + hackers_delight(20) + advanced(28) + chains(25) = 108 total. |
| DCE cycle handling | **PASS** | A->B->A cycle: 0 dead blocks (correctly reachable). Unreachable subgraph: correctly identified and removed. |

---

## New Issues Found

### [CRITICAL] VM handler classifier misclassifies handlers ending with RET

**Severity:** CRITICAL
**Module:** `d810g_engine/virtualization/disasm.py`

The `classify_handler_by_disasm` function checks `has_ret and total_meaningful <= 2` as the FIRST classification rule. This fires even when there are meaningful arithmetic, bitwise, or stack instructions before the RET. Since real VM handlers almost always end with RET or JMP to the dispatcher, this bug affects essentially all real-world usage.

**Test results:**

| Handler bytes | Semantics | Expected | Actual |
|--------------|-----------|----------|--------|
| `add eax, ebx; ret` | ADD | add | **ret** |
| `xor rax, rbx; ret` | XOR | xor | **ret** |
| `push rax; push rbx; ret` | PUSH | push | **ret** |
| `add rax, rbx; mov [rdi], rax; ret` | ADD | add | **ret** |
| `nop; ret` | NOP | nop | **ret** |

**Root cause:** The classification priority puts RET before arithmetic/bitwise/stack checks. The condition `total_meaningful <= 2` includes ALL instruction categories (move + arith + bitwise + stack), so a handler with one arithmetic instruction and one RET has total_meaningful=1, which passes `<= 2`.

**Why tests pass:** Existing tests (`test_add_reg_reg`, etc.) test instructions WITHOUT a trailing RET. Real handlers always end with RET/JMP.

**Fix:** Either exclude `has_ret` from firing when `arith_count > 0 or bitwise_count > 0 or stack_count > 0`, or move the RET classification to the END of the priority chain (only classify as "ret" when NO other semantic category matched).

---

### [CRITICAL] Advanced opaque predicate classifier returns wrong results via integer-mode fallback

**Severity:** CRITICAL
**Module:** `d810g_engine/opaque/advanced.py`

When the bitvector analysis classifies a predicate as "dynamic", the advanced classifier falls back to integer arithmetic (unbounded integers). This ignores bitvector overflow, producing incorrect results.

**Example:** `x * x >= 0` (32-bit signed)
- Bitvector analysis: **dynamic** (correct -- overflow makes `x*x` negative for `x=-966451019`)
- Integer fallback: **always_true** (mathematically correct for integers, wrong for 32-bit)
- Final classification: **always_true** (WRONG for a 32-bit binary)

**Impact:** If used to eliminate an opaque predicate, this would remove a branch that is actually reachable, causing incorrect deobfuscation. The note field says "may differ from bitvector semantics" but the `classification` field still says `always_true`, and callers would act on the classification, not the note.

**Mitigating factor:** The pipeline's `eliminate_predicates` uses the basic `classify_predicate` (bitvector-only), NOT the advanced classifier. The bug affects only direct API callers using `opaque.classify_advanced` or `opaque.batch_advanced`.

**Fix:** The integer-mode result should NOT override the bitvector result. Either: (a) report it as `classification: "dynamic"` with a separate `integer_proof: "always_true"` field, or (b) only use integer mode for purely arithmetic predicates where overflow cannot occur.

---

### [IMPORTANT] MBA rule `hd_sub_3` fails Z3 verification

**Severity:** IMPORTANT
**Module:** `data/rules/mba_hackers_delight.json`

Rule `hd_sub_3` fails Z3 equivalence check:
- **Pattern:** `x ^ y + 2 * (~x & y)`
- **Replacement:** `x - y + 2 * y`

Two bugs:
1. **Operator precedence:** The pattern is parsed as `x ^ (y + (2 * (~x & y)))` due to operator precedence (& binds tighter than +, + binds tighter than ^). The intended expression was likely `(x ^ y) + (2 * (~x & y))`.
2. **Wrong operator:** The correct identity is `(x ^ y) - 2 * (~x & y) = x - y` (subtraction, not addition). The replacement `x - y + 2 * y` simplifies to `x + y`, which is a completely different identity.

**Impact:** If the pattern ever matches (unlikely due to precedence parsing), the replacement would produce incorrect code. The verifier would catch this (returns False), but only if `verify=True`.

**Fix:** Remove or correct the rule. Correct version: pattern `(x ^ y) - 2 * (~x & y)`, replacement `x - y`.

---

### [IMPORTANT] `simplify_expression_deep` returns `verified=False` when expression is unchanged

**Severity:** IMPORTANT
**Module:** `d810g_engine/mba/__init__.py`

When no rule matches and the expression stays the same, `simplify_expression_deep` returns `verified=False`. An expression is trivially equivalent to itself, so this should be `True`.

**Code (line 101-103):**
```python
verified = False
if verify and current != expr_str:
    verified = verify_equivalence(expr_str, current)
```

When `current == expr_str`, the condition is False and `verified` stays False.

**Impact:** Callers checking `verified` to decide whether to apply a simplification will see `False` on unchanged expressions, which is misleading. Could cause downstream logic to reject valid (unchanged) expressions.

**Fix:** Change to:
```python
if verify and current != expr_str:
    verified = verify_equivalence(expr_str, current)
else:
    verified = True  # unchanged expression is trivially equivalent
```

---

### [MINOR] MBA pipeline not included in deobfuscation pipeline

**Severity:** MINOR
**Module:** `d810g_engine/pipeline/orchestrator.py`

The pipeline runs 6 passes: deflat_ollvm, deflat_tigress, bcf, opaque, dce, strings. MBA simplification is NOT included, despite being a core deobfuscation capability. Users must call `mba.simplify` or `mba.simplify_deep` separately.

This is understandable because MBA operates on individual expressions rather than block graphs, but it means the pipeline cannot simplify MBA-obfuscated arithmetic within blocks.

---

### [MINOR] Parser operator precedence differs from C standard

**Severity:** MINOR
**Module:** `d810g_engine/parser.py` and `d810g_engine/mba/matcher.py`

Both parsers use identical precedence: `* / % > << >> > & > + - > ^ > | > comparison`

Standard C precedence: `* / % > + - > << >> > < <= > >= > == != > & > ^ > |`

Key difference: `&` binds tighter than `+ -` in D810G, but looser in C. Expression `x + y & z` is parsed as `x + (y & z)` by D810G but `(x + y) & z` in C.

**Impact:** Users copying expressions from Ghidra/IDA decompiler output (which uses C precedence) would get silently different parsing. The two parsers are internally consistent and all rules are written for this precedence, so it does not cause incorrect rule matching within the system. Only affects externally-provided expressions.

---

## Updated Scores (1-10)

| Dimension | Round 1 | Round 2 | Change | Notes |
|-----------|---------|---------|--------|-------|
| MBA simplification | 3 | 7 | +4 | 108 rules, deep simplify, Z3 verification. One broken rule. |
| Opaque predicates | 4 | 7 | +3 | Error handling solid, hex/modulo/empty all handled. Advanced classifier has false-positive risk. |
| Pipeline integration | 3 | 8 | +5 | State propagation, patch dedup, fixpoint convergence all working correctly. |
| String decryption | 3 | 7 | +4 | False positives reduced from 190+ to ~4. Multi-method support (XOR, RC4, multi-byte, ROT). |
| Parser quality | 2 | 8 | +6 | Consolidated parser, full operator support, good error messages. Non-standard precedence documented. |
| VM analysis | 4 | 5 | +1 | Capstone disassembly integrated but RET-priority bug severely limits real-world accuracy. |
| Test coverage | 6 | 8 | +2 | 373 tests, all passing. But critical scenarios (handler+ret) not covered. |
| Overall | 3.6 | 7.1 | +3.5 | Major improvement across the board. Two critical issues remain. |

---

## Remaining Gap vs D-810

| Feature | D-810 | D810G | Gap |
|---------|-------|-------|-----|
| MBA rules | ~50 built-in | 108 JSON-based | Parity achieved |
| Opaque predicates | Basic Z3 | Z3 + integer + pattern | Feature parity (but integer-mode is buggy) |
| Control flow recovery | IDA microcode integration | Block-graph based | No IDA integration (by design) |
| String decryption | Targeted patterns | Brute-force + scoring | Different approach, adequate for common cases |
| VM deobfuscation | Minimal | Capstone-based classification | Promising but classification accuracy needs fix |
| Pipeline | Single-pass | Multi-pass with fixpoint | Improvement over D-810 |
| Integration | IDA plugin | Ghidra plugin + standalone | Broader platform support |

---

## Next Priority Actions

1. **[P0] Fix VM handler RET classification priority** -- Move RET check below arithmetic/bitwise/stack checks, or add guard conditions. This blocks real-world VM analysis.

2. **[P0] Fix advanced opaque integer-mode fallback** -- Do not allow integer-mode to override bitvector classification. Report integer proofs as advisory, not authoritative.

3. **[P1] Fix `hd_sub_3` rule** -- Either correct the pattern/replacement or remove the rule entirely. Consider adding a CI check that verifies all rules pass Z3 equivalence.

4. **[P1] Fix `verified=False` on unchanged expressions** -- One-line fix in `simplify_expression_deep`.

5. **[P2] Add real-world handler test cases** -- Add tests with trailing RET/JMP instructions to catch classification priority bugs.

6. **[P2] Document or reconsider parser precedence** -- Either switch to C-standard precedence (breaking change for rules) or add clear documentation warning users about the difference.

7. **[P3] Consider adding MBA pass to pipeline** -- Would require expression-level integration with block instructions/pcode.
