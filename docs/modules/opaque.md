---
layout: default
title: Opaque Predicates
---

**English** | [中文](../cn/modules/opaque)

# Opaque Predicate Elimination

Opaque predicates are conditions that always evaluate the same way, inserted by obfuscators to add fake branches.

## Detection Methods

### Standard (Z3 Bitvector)
Checks satisfiability of both the predicate and its negation using Z3's bitvector theory.

### Advanced (Integer Arithmetic)
Falls back to Z3's integer theory for predicates involving modular arithmetic that bitvector overflow may obscure.

### Number Theory Patterns
Matches against known mathematical tautologies:
- `x² mod 4 ∈ {0, 1}` — always true
- `x(x+1) mod 2 = 0` — always true (consecutive product is even)
- `x + (x+1) + (x+2) mod 3 = 0` — always true

## Examples

| Predicate | Classification | Method |
|-----------|---------------|--------|
| `x == x` | always_true | bitvector |
| `(x & 1) == 2` | always_false | bitvector |
| `x*(x+1) % 2 == 0` | always_true | integer |
| `x > 5` | dynamic | — |

[← Back to Home](../)
