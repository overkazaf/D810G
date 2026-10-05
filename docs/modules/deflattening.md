---
layout: default
title: Control Flow Deflattening
---

# Control Flow Deflattening

D810G recovers original control flow from obfuscated functions by detecting and reversing the state machine transformation applied by OLLVM and Tigress.

## Supported Patterns

### OLLVM Switch-Dispatch

OLLVM converts the function's basic blocks into cases of a giant `switch(state)` statement. Each original block updates the state variable and jumps back to the dispatcher.

```
Original:                    After OLLVM CFF:

  ┌───────┐                  ┌──────────────┐
  │ entry │                  │  dispatcher   │◄────┐
  └───┬───┘                  │ switch(state) │     │
      │                      └┬──┬──┬──┬────┘     │
  ┌───▼───┐               ┌──▼┐┌▼─┐┌─▼┐┌──▼──┐    │
  │ if()  │               │0xA││0xB││0xC││ ret │    │
  └─┬───┬─┘               │s= ││s= ││s= │└─────┘    │
    │   │                  │0xB││0xC││0xD│           │
    ▼   ▼                  └─┬─┘└─┬─┘└─┬─┘           │
  return                     └────┴────┴──────────────┘
```

**D810G's approach:**
1. Detect the dispatcher block (high in-degree + high out-degree)
2. Use **Unicorn** to emulate each case block and trace state variable writes
3. Build a state transition map: state_value → next_block
4. Use **Keystone** to assemble direct `jmp` instructions replacing the state update + dispatcher jump
5. **NOP** out dead code

### Tigress Indirect Jump Table

Tigress uses `jmp [table + state * 8]` instead of a switch statement. D810G detects the jump table in `.rodata` and resolves each entry.

### Tigress If-Chain

Tigress may also use sequential `if/else` comparisons instead of a switch. D810G detects chains of 3+ comparison blocks.

## Architecture Support

| Arch | Emulation | Patching |
|------|-----------|----------|
| x86_64 | Unicorn UC_ARCH_X86 | `jmp rel32` |
| ARM64 | Unicorn UC_ARCH_ARM64 | `b offset` |
| ARM32 | Unicorn UC_ARCH_ARM | `b offset` |

## API

```python
# JSON-RPC
{"method": "deflat.run", "params": {"blocks": [...], "binary_hex": "...", "arch": "x86_64"}}
{"method": "deflat.tigress", "params": {"blocks": [...], "binary_hex": "..."}}
```

[← Back to Home](../)
