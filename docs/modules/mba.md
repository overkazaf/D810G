---
layout: default
title: MBA Simplification
---

# MBA Simplification

Mixed Boolean-Arithmetic (MBA) expressions are used by obfuscators like OLLVM to disguise simple operations. D810G automatically simplifies them using pattern matching verified by Z3.

## How It Works

```
Obfuscated:    (x | y) - (x & y)     ← looks complex
Simplified:    x ^ y                  ← simple XOR, Z3-verified equivalent
```

## Rule Sets

| File | Rules | Description |
|------|-------|-------------|
| `mba_basic.json` | 10 | XOR, AND, OR, addition identities |
| `mba_hackers_delight.json` | 25 | Bit tricks: abs, min, max, De Morgan |
| `mba_ollvm.json` | 15 | OLLVM-specific substitution patterns |
| `mba_constant_folding.json` | 10 | Algebraic identities, zero/one/self |

## Multi-Pass Deep Simplification

D810G applies rules iteratively, simplifying sub-expressions bottom-up until no more rules match (fixpoint):

```
Input:    ((x | y) - (x & y)) ^ ((x | y) - (x & y))
Step 1:   (x ^ y) ^ ((x | y) - (x & y))    [mba_xor_1]
Step 2:   (x ^ y) ^ (x ^ y)                 [mba_xor_1]
Step 3:   0                                  [mba_zero_1]
Result:   Z3 verified equivalent ✓
```

## Interactive Rule Editor

```
d810g> verify (x & y) + (x ^ y) = x | y
  32-bit: EQUIVALENT

d810g> add my_rule ~(~x & ~y) = x | y
  Added [verified]

d810g> save my_rules.json
  Saved 1 rule
```

## API

```python
{"method": "mba.simplify", "params": {"expression": "(x|y)-(x&y)", "rules": "mba_basic.json"}}
{"method": "mba.simplify_deep", "params": {"expression": "...", "max_iterations": 10}}
```

[← Back to Home](../)
