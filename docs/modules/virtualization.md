---
layout: default
title: VM Devirtualization
---

**English** | [中文](../cn/modules/virtualization)

# VM Devirtualization

D810G detects and analyzes Tigress VM-protected functions — recovering the custom bytecode instruction set and generating pseudocode.

## Two-Phase Analysis

### Phase 1: VM Analysis (`vm.analyze`)
- Detect the VM dispatcher (block with high in-degree and out-degree)
- Identify handler blocks (successors that loop back)
- Classify handler semantics: mov, add, sub, load, store, branch, ret, etc.

### Phase 2: Bytecode Tracing (`vm.trace`)
- Simulate the fetch-decode-execute loop over the bytecode
- Record each executed instruction with operands
- Generate pseudocode from the trace

## Example Output

```
VM detected at 0x1000 with 5 handlers: mov, add, load, branch, ret

Pseudocode:
  r0 = 42
  r1 = 10
  r2 = r0 + r1
  return r2
```

[← Back to Home](../)
