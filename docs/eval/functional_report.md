# D810G Functional Evaluation Report

**Date:** 2026-10-07
**Scope:** Full functional testing of all D810G engine components
**Environment:** Python 3.12.5, Z3 solver, macOS Darwin 25.6.0
**Test suite:** 201 existing tests (all passing) + 55 manual functional tests

---

## Summary

| Metric | Count |
|--------|-------|
| Tests run | 55 (manual) + 201 (automated) |
| Passed | 233 |
| Failed | 23 |
| Issues found | 16 |
| CRITICAL | 4 |
| IMPORTANT | 7 |
| MINOR | 5 |

**Existing test suite: 201/201 PASS** (0.77s). The automated tests are solid but
do not cover the edge cases documented below.

---

## CRITICAL Issues

### [FAIL] MBA: x >> 1 simplified to "x" instead of "x / 2"

**Input:** `x >> 1` with rules `mba_hackers_delight.json`
**Expected:** Simplified to `x / 2` (or flagged as unsupported)
**Actual:** Simplified to `x` -- **silently produces wrong code**
**Verified:** Z3 reports `True` (also broken -- see below)
**Impact:** CRITICAL -- applying this rule would corrupt decompiled output

**Root cause:** Rule `hd_div2_1` has replacement `x / 2`, but the
expression parser does not recognize `/` as an operator. The tokenizer
(`matcher.py:_tokenize`) skips unknown characters, so `x / 2` is
tokenized as `['x', '2']`. The parser returns the first atom `x` and
silently ignores the trailing `2`.

The Z3 verifier (`verifier.py`) has the **same tokenizer bug**: it
also skips `/` and `>>`, so it parses both `x >> 1` and `x` as the
same expression `x`, reports them as equivalent, and the `--verify`
flag gives a false "OK".

**Affected rule:** `hd_div2_1`

---

### [FAIL] MBA: abs/min/max/sign rules produce bare variable names

**Input:** `(x ^ (x >> 31)) - (x >> 31)` with `mba_hackers_delight.json`
**Expected:** `abs(x)` or error
**Actual:** `abs` (a bare variable name, parenthesized argument silently dropped)
**Impact:** CRITICAL -- 4 rules silently produce wrong simplifications

The parser treats function names (`abs`, `min`, `max`, `sign`) as
variable identifiers. The `(x)` or `(x, y)` that follows is parsed as
a parenthesized sub-expression but is never consumed (the parser
returns after seeing the variable atom and ignores remaining tokens).

**Affected rules (all produce wrong output when matched):**

| Rule ID | Replacement | Actual output |
|---------|-------------|---------------|
| `hd_abs_1` | `abs(x)` | `abs` |
| `hd_min_1` | `min(x, y)` | `min` |
| `hd_max_1` | `max(x, y)` | `max` |
| `hd_sign_1` | `sign(x)` | `sign` |

---

### [FAIL] Z3 Verifier: shift operators (<<, >>) silently ignored

**Input:** `verify_equivalence("x << 1", "x + x", bit_width=32)`
**Expected:** `True`
**Actual:** `False` (because `x << 1` is parsed as just `x`)

The verifier's tokenizer (`verifier.py:_OP_CHARS`) only includes
`+-*&|^~()`. It does **not** handle `<<`, `>>`, `/`, `%`, or
comparison operators. Unknown characters are silently skipped, making
the verifier return incorrect results for any expression containing
these operators. This means:

- `x << 1 == x` verifies as True (both parsed as `x`)
- `x << 1 == x * 2` verifies as False (parsed as `x == x * 2`)

**Impact:** CRITICAL -- Z3 verification gives false confidence. 7 of
60 rules correctly show as FAILED during `--verify`, but 1 rule
(`hd_div2_1`) shows OK despite being wrong because the verifier
cannot parse either side correctly.

---

### [FAIL] Pipeline: fixpoint detection broken -- same patches found repeatedly

**Input:** Block graph with 1 unreachable block, `max_iterations=5`, pass `dce`
**Expected:** Dead block found in iteration 1, no changes in iteration 2, fixpoint
**Actual:** Same dead block found 5 times (once per iteration), fixpoint=False

**Root cause:** `run_pipeline()` in `orchestrator.py` never updates
`params` between iterations. Each pass receives the original input
graph, so passes that find issues (like DCE finding a dead block) will
report the same issue every iteration. The fixpoint loop runs to
exhaustion instead of converging.

```python
# orchestrator.py line 139: passes always get the ORIGINAL params
pass_result = pipeline_pass.run(params)  # params never updated
```

**Impact:** CRITICAL -- the pipeline reports inflated patch counts and
never reaches fixpoint when any pass produces patches.

---

## IMPORTANT Issues

### [FAIL] CLI: empty string crashes simplify with unhandled ValueError

**Input:** `python -m d810g_engine cli simplify ""`
**Expected:** Helpful error message like "Error: empty expression"
**Actual:** Raw Python traceback: `ValueError: Unexpected end of expression`
**Impact:** IMPORTANT -- poor user experience; no error handling at CLI layer

---

### [FAIL] CLI: empty/non-boolean expression crashes opaque with Z3Exception

**Input:** `python -m d810g_engine cli opaque ""`
**Expected:** Helpful error message
**Actual:** Raw traceback: `z3.z3types.Z3Exception: Value cannot be converted into a Z3 Boolean value`

Also crashes for any expression without a comparison operator:
- `python -m d810g_engine cli opaque "not a valid expression"` -- same crash
- `python -m d810g_engine cli opaque "x + y"` -- same crash (no `==`, `<`, etc.)

**Root cause:** `classify_predicate()` passes the result of `_eval()`
directly to Z3's `Not()`, but if the expression has no comparison
operator, `_eval()` returns a BitVec (not a Bool), and Z3 rejects it.

**Impact:** IMPORTANT -- any non-boolean expression crashes

---

### [FAIL] Opaque: multi-variable predicate (x + y) == (y + x) crashes

**Input:** `classify_predicate("(x + y) == (y + x)")`
**Expected:** `always_true` (addition is commutative in bitvectors)
**Actual:** `Z3Exception: Value cannot be converted into a Z3 Boolean value`

**Root cause:** The opaque predicate parser scans for `==` by
iterating right-to-left, but the parenthesized expression structure
causes it to fail to split the string at the `==` operator. The
parser's depth-tracking logic does not correctly handle this case,
resulting in the expression being treated as an arithmetic expression
(returning a BitVec instead of a Bool).

**Impact:** IMPORTANT -- multi-variable opaque predicates with
parenthesized sub-expressions on both sides are not supported

---

### [FAIL] Opaque: modulo operator (%) not supported

**Input:** `classify_predicate("(x * (x + 1)) % 2 == 0")`
**Expected:** `always_true` (consecutive integers product is always even)
**Actual:** `dynamic` -- the `%` operator is not in the parser, so
`(x * (x + 1)) % 2` is treated as a single variable name

The `variables` field in the result confirms: `["(x * (x + 1)) % 2"]`
-- the entire left side of `==` is treated as one opaque identifier.

**Impact:** IMPORTANT -- number-theoretic opaque predicates using
modular arithmetic cannot be detected

---

### [FAIL] CLI: nonexistent rules file gives raw FileNotFoundError

**Input:** `python -m d810g_engine cli simplify --rules nonexistent.json "x + y"`
**Expected:** `Error: rules file 'nonexistent.json' not found in data/rules/`
**Actual:** Raw Python traceback: `FileNotFoundError: [Errno 2] No such file...`
**Impact:** IMPORTANT -- unhelpful error message

---

### [FAIL] String decryption: ROT-N fails to find correct decryption

**Input:** `'password123'` encrypted with ROT-13 (add 13 mod 256)
**Expected:** Decryption found with rotation=243 (256-13)
**Actual:** 5 candidates returned, none is `'password123'`

**Root cause:** `try_sub_table_decrypt()` returns at most 5 results
sorted by score. Many ROT-N values produce "printable" output that
scores >= 0.7, so the correct decryption (rot=243) is crowded out by
false positives that happen to score equally well.

**Impact:** IMPORTANT -- ROT-N decryption has a high false positive
rate that can drown out correct results

---

### [WARN] String decryption: XOR has 190+ false positives per input

**Input:** 20-byte URL encrypted with XOR key 0x55
**Expected:** Correct decryption found (it is -- ranked #1 by score)
**Actual:** 190 total candidates, only 1 correct -- 0.5% signal-to-noise

For a 2-byte input: 190 candidates, essentially all false positives.
For all-zeros input (20 bytes): 194 candidates including strings like
`"00000000..."` and `"11111111..."`.

The decryptor does find the correct answer, but the volume of false
positives means downstream consumers must implement their own
ranking/filtering. This is a known limitation of brute-force XOR
decryption but worth documenting.

**Impact:** IMPORTANT -- false positive rate makes automated string
recovery unreliable without additional filtering

---

## MINOR Issues

### [WARN] CLI: odd-length hex string crashes string decryptor

**Input:** `try_xor_decrypt("ABC")` (3 hex chars, not valid hex pair)
**Expected:** Error message or empty result
**Actual:** `ValueError: non-hexadecimal number found in fromhex() arg at position 3`
**Impact:** MINOR -- raw exception, should validate input

---

### [WARN] VM Tracer: missing 'handlers' key gives raw KeyError

**Input:** `trace_vm({"bytecode_hex": "0102"})` (no `handlers` field)
**Expected:** Error message about missing required field
**Actual:** `KeyError: 'handlers'`
**Impact:** MINOR -- should validate required parameters

---

### [WARN] VM Tracer: jmp/branch not followed during tracing

**Input:** Bytecode with `jmp 5` instruction
**Expected:** Tracer follows the jump (or documents that it doesn't)
**Actual:** Tracer continues linearly past the jump instruction

This is a design limitation (the tracer does linear decoding, not
emulation), but it means branch-heavy VM programs produce incorrect
traces. The behavior is undocumented.

**Impact:** MINOR -- expected for a static tracer, but should be
documented

---

### [WARN] Single-pass simplify only matches root AST node

**Input:** `((x | y) - (x & y)) + z` (MBA pattern nested inside larger expr)
**Expected:** Simplified to `(x ^ y) + z`
**Actual:** `(no simplification found)` -- single-pass mode only checks root

**Workaround:** Use `--deep` flag for recursive sub-expression matching.
The deep mode works correctly for this case.

**Impact:** MINOR -- `--deep` is available but the default mode's
limitation is not obvious to users

---

### [WARN] Long multi-term expression not simplified

**Input:** `(x | y) - (x & y) + (a | b) - (a & b) + (c | d) - (c & d)`
**Expected:** Deep mode should simplify each pair
**Actual:** Single pass: no match. Deep mode not tested for this
(would require operator precedence to group terms correctly).

**Impact:** MINOR -- complex real-world expressions may need manual
decomposition

---

## Passing Tests (Highlights)

### [PASS] CLI: All 6 subcommands have working --help
All subcommands (`simplify`, `opaque`, `rules`, `batch`, `pipeline`,
`interactive`) display correct help text. Running with no command
shows usage and returns exit code 1.

### [PASS] MBA: All 10 basic rules match and verify correctly
Every rule in `mba_basic.json` matches its pattern expression and
produces the correct simplification, verified by Z3.

### [PASS] MBA: All 10 constant folding rules work
Rules like `x + 0 -> x`, `x * 0 -> 0`, `x - x -> 0` all match and
verify.

### [PASS] MBA: OLLVM rules (13 of 15) work correctly
13 rules in `mba_ollvm.json` match and verify. The 2 shift-based
rules (`ollvm_mul_1`, `ollvm_mul_2`) match correctly and produce
correct output (`(x << 3) - x -> x * 7`), but Z3 verification fails
because the verifier doesn't support shifts.

### [PASS] MBA: Commutative matching works
`(x & y) + (x | y)` correctly matches `mba_add_1` which has pattern
`(x | y) + (x & y)` -- the commutative flag enables swapped matching.

### [PASS] MBA: Deep simplification with fixpoint
`(x | 0) | 0 | 0 | 0` correctly simplifies through 4 steps to `x`
and reaches fixpoint. Multi-rule chains like
`((x | y) - (x & y)) | 0 -> (x ^ y) | 0 -> x ^ y` work correctly.

### [PASS] Opaque: Basic predicates classified correctly
- `x == x` -> always_true (8/16/32/64 bit, signed and unsigned)
- `x != x` -> always_false
- `x >= x` -> always_true
- `x > x` -> always_false
- `x > 0` -> dynamic
- `(x & 1) == 2` -> always_false (64-bit)
- `(x * x * x) >= 0` -> dynamic (correct: signed overflow)

### [PASS] Opaque: JSON output well-structured
JSON output includes expression, classification, and variables list.

### [PASS] String decryption: XOR single-byte works
URL encrypted with key 0x55 correctly found as top-ranked result.

### [PASS] String decryption: RC4 works
RC4-encrypted "Hello World" with single-byte key correctly decrypted.

### [PASS] String decryption: Multi-byte XOR works
39-byte string encrypted with 2-byte key recovered with correct key.

### [PASS] String decryption: Empty input handled gracefully
Empty hex string returns 0 candidates without crashing.

### [PASS] Pipeline: Empty blocks handled
Empty block list produces status "completed" with 0 patches.

### [PASS] Pipeline: Pass filtering works
`passes: ["dce", "opaque"]` correctly runs only those 2 passes.

### [PASS] Pipeline: Error isolation
Individual pass failures are caught and reported without crashing the
entire pipeline.

### [PASS] VM Tracer: Complete pseudocode generation
All 18 instruction semantics (mov, load, store, add, sub, mul, and,
or, xor, not, cmp, branch, jmp, call, push, pop, load_imm, nop, ret)
produce correct pseudocode output.

### [PASS] VM Tracer: Empty bytecode handled
Returns 0 instructions without error.

### [PASS] VM Tracer: Unknown opcodes recorded
Unknown opcodes are recorded as "unknown" with pc advancement of 1
byte, allowing tracing to continue.

### [PASS] VM Tracer: max_instructions limit respected
With 100 NOP bytes and max_instructions=10, exactly 10 instructions
traced.

### [PASS] VM Tracer: Stops at ret
Tracing stops when a `ret` instruction is encountered.

### [PASS] Batch mode: works with stdin
Processes expressions line by line, skips comments and blank lines,
reports summary statistics.

### [PASS] CLI: Special characters don't cause injection
Expression `x + y; echo pwned` is safely handled (`;` skipped by
tokenizer, no shell injection).

### [PASS] CLI: Very long expressions handled
200-term expression `x + x + x + ...` (1000+ characters) parses and
processes without error or timeout.

### [PASS] Test suite: 201/201 tests pass in 0.77s

---

## Recommendations (Priority Order)

1. **[P0] Fix or disable the 5 broken rules** (`hd_div2_1`,
   `hd_abs_1`, `hd_min_1`, `hd_max_1`, `hd_sign_1`) that silently
   produce wrong simplifications. Either add `/` and function-call
   support to the parser, or remove these rules and document them as
   planned features.

2. **[P0] Add shift operators to the Z3 verifier** tokenizer so that
   rules using `<<` and `>>` can be properly verified.

3. **[P0] Fix pipeline fixpoint loop** to update `params` between
   iterations, or change the architecture so passes communicate state
   changes.

4. **[P1] Add input validation and error handling** at the CLI layer
   (`cli.py`) to catch empty expressions, parse errors, and missing
   files before they reach internal code.

5. **[P1] Add `%` operator support** to the opaque predicate parser
   to enable number-theoretic predicate detection.

6. **[P1] Fix opaque parser** to handle parenthesized
   sub-expressions on both sides of comparison operators (the
   `(x + y) == (y + x)` case).

7. **[P2] Reduce false positive rate** in XOR string decryption by
   adding n-gram scoring or printable-range filtering beyond the
   current 0.7 threshold.

8. **[P2] Add integration tests** for the edge cases documented in
   this report (empty input, broken rules, pipeline fixpoint, etc.).

---

## Rules Verification Summary

| File | Total | Pass | Fail | Notes |
|------|-------|------|------|-------|
| mba_basic.json | 10 | 10 | 0 | All correct |
| mba_constant_folding.json | 10 | 10 | 0 | All correct |
| mba_hackers_delight.json | 25 | 19 | 6 | 4 use unsupported functions, 1 shift, 1 precedence |
| mba_ollvm.json | 15 | 13 | 2 | 2 use shifts (output correct, verify broken) |
| **Total** | **60** | **52** | **8** | |

Of the 8 failures:
- 5 rules produce **wrong output** when matched (CRITICAL)
- 2 rules produce correct output but cannot be Z3-verified (verifier limitation)
- 1 rule (`hd_sub_3`) may have an algebraic error in its definition
