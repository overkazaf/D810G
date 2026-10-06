---
layout: default
title: Tutorial — D810G in Action
---

# D810G Tutorial: Step-by-Step Deobfuscation

This tutorial demonstrates D810G's capabilities using concrete examples.

## Example 1: OLLVM Control Flow Flattening

### The Problem

OLLVM's `-fla` (flatten) flag transforms a function's natural control flow into a state machine.
Every original basic block becomes a case in a giant `switch(state)` loop.

### Before D810G

```c
// Ghidra decompiler output — obfuscated check_license()
int check_license(char *param_1) {
    int local_10 = 0x2b8a7c3f;  // state variable
    int local_1c = 0;
    int local_18 = 0;
    int local_14;
    
    while (true) {
        switch(local_10) {
        case 0x2b8a7c3f:
            local_14 = *(char *)(param_1 + local_18);
            if (local_14 == 0)
                local_10 = 0x7d3e9a15;
            else
                local_10 = 0x4f1c82d6;
            break;
        case 0x4f1c82d6:
            local_1c = local_1c + local_14;
            local_18 = local_18 + 1;
            local_10 = 0x2b8a7c3f;
            break;
        case 0x7d3e9a15:
            if (local_1c == 0x1a4)
                local_10 = 0xa5b3c1d2;
            else
                local_10 = 0xe8f47209;
            break;
        case 0xa5b3c1d2: return 1;
        case 0xe8f47209: return 0;
        }
    }
}
```

5 "blocks" are multiplexed through a dispatcher — impossible to read at a glance.

### After D810G (right-click → D810G → Deobfuscate Function)

```c
int check_license(char *param_1) {
    int sum = 0;
    int i = 0;
    
    while (*(char *)(param_1 + i) != '\0') {
        sum += *(char *)(param_1 + i);
        i++;
    }
    
    if (sum == 0x1a4) {
        return 1;
    }
    return 0;
}
```

The original loop + condition structure is instantly recognizable.

**What D810G did:**
1. Detected the switch-dispatch pattern (dispatcher at entry, 5 case blocks)
2. Used Unicorn to emulate each case block and trace state variable writes
3. Built the state transition map: `0x2b8a7c3f → loop_head, 0x4f1c82d6 → accumulate, ...`
4. Replaced state assignments + dispatcher jumps with direct `jmp` instructions
5. Ghidra re-decompiled the patched function → clean output

---

## Example 2: MBA Expression Simplification

### The Problem

OLLVM's `-sub` (substitution) flag replaces simple operations with mathematically equivalent but complex expressions.

### Before D810G

```c
// x ^ y obfuscated as:
result = (x | y) - (x & y);

// x + y obfuscated as:
result = (x ^ y) + 2 * (x & y);

// x - y obfuscated as:
result = x + (~y + 1);
```

### D810G CLI

```
$ d810g cli simplify "(x | y) - (x & y)"
  → (x ^ y)  [Z3 verified]

$ d810g cli simplify "(x ^ y) + 2 * (x & y)"
  → (x + y)  [Z3 verified]

$ d810g cli simplify --deep "((x | y) - (x & y)) ^ ((x | y) - (x & y))"
  Step 1: ((x ^ y) ^ ((x | y) - (x & y)))  [mba_xor_1]
  Step 2: ((x ^ y) ^ (x ^ y))              [mba_xor_1]
  Step 3: 0                                 [mba_zero_1]
  Final: Z3 verified equivalent
```

---

## Example 3: Opaque Predicate + BCF Removal

### The Problem

OLLVM's `-bcf` flag inserts fake branches guarded by conditions that are always true or always false.

### Before D810G

```c
// Bogus: (x * x) >= 0 is ALWAYS true
if ((x * x) >= 0) {
    result = real_computation(x, y);
} else {
    result = garbage_code();  // dead code
}

// Bogus: (x & 1) == 2 is ALWAYS false
if ((x & 1) == 2) {
    result = more_garbage();  // dead code
} else {
    result = result + real_stuff();
}
```

### D810G Analysis

```
$ d810g cli opaque "(x * x) >= 0" --unsigned
  → ALWAYS TRUE — opaque, can be eliminated

$ d810g cli opaque "(x & 1) == 2"
  → ALWAYS FALSE — opaque, can be eliminated
```

D810G removes the bogus branches, then Dead Code Elimination cleans up the unreachable blocks.

---

## Example 4: String Decryption

### The Problem

OLLVM encrypts string literals with XOR at compile time, decrypting them at runtime.

### D810G Decryption

```
Encrypted bytes: 2d 2a 26 22 27 1f 0a 36 22 35 2a 21
D810G found:     "Hello, World" (XOR key=0x45, score=1.0)
```

---

## Full Pipeline

For heavily obfuscated binaries, run all passes at once:

```
$ d810g cli pipeline obfuscated_function.json

Pipeline completed in 2 iteration(s):
  ✅ [   deflat_ollvm] deobfuscated — 5 patches
  ⚪ [ deflat_tigress] no_cff_detected — 0 patches
  ✅ [            bcf] bcf_removed — 2 patches
  ✅ [         opaque] — 3 patches
  ✅ [            dce] dead_code_eliminated — 2 patches
  ⚪ [        strings] no_encrypted_strings — 0 patches
  Total: 12 patches applied, fixpoint reached
```
