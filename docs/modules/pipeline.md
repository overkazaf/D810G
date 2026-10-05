---
layout: default
title: Deobfuscation Pipeline
---

**English** | [中文](../cn/modules/pipeline)

# Multi-Pass Deobfuscation Pipeline

The pipeline chains all analysis passes and iterates until no more changes are made.

## Pass Order

```
1. deflat_ollvm    — OLLVM control flow deflattening
2. deflat_tigress  — Tigress CFF deflattening
3. bcf             — Bogus control flow removal
4. opaque          — Opaque predicate elimination
5. dce             — Dead code elimination
6. strings         — String decryption
```

## Fixpoint Iteration

The pipeline repeats all passes until a round produces zero patches (fixpoint) or `max_iterations` is reached.

## CLI Usage

```bash
# Create input.json with blocks and binary_hex
PYTHONPATH=python python -m d810g_engine cli pipeline input.json

# Select specific passes
PYTHONPATH=python python -m d810g_engine cli pipeline input.json --passes bcf dce opaque
```

[← Back to Home](../)
