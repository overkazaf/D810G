"""Analyze and devirtualize Tigress VM-protected functions."""

from __future__ import annotations
from typing import Any


class VMHandler:
    """Represents a single VM opcode handler."""

    def __init__(self, opcode: int, address: int, semantics: str = "unknown",
                 operand_count: int = 0, description: str = "") -> None:
        """Initialize a handler with its opcode, address, and semantics."""
        self.opcode = opcode
        self.address = address
        self.semantics = semantics
        self.operand_count = operand_count
        self.description = description

    def to_dict(self) -> dict[str, Any]:
        """Serialize the handler to a JSON-compatible dict."""
        return {
            "opcode": self.opcode,
            "opcode_hex": f"0x{self.opcode:02x}",
            "address": self.address,
            "semantics": self.semantics,
            "operand_count": self.operand_count,
            "description": self.description,
        }


class VMContext:
    """Represents the VM's execution context."""

    def __init__(self) -> None:
        """Initialize an empty VM context."""
        self.handlers: list[VMHandler] = []
        self.bytecode_addr: int = 0
        self.bytecode_size: int = 0
        self.register_count: int = 0
        self.dispatcher_addr: int = 0
        self.pc_register: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the VM context to a JSON-compatible dict."""
        return {
            "bytecode_addr": self.bytecode_addr,
            "bytecode_size": self.bytecode_size,
            "register_count": self.register_count,
            "dispatcher_addr": self.dispatcher_addr,
            "pc_register": self.pc_register,
            "handler_count": len(self.handlers),
            "handlers": [h.to_dict() for h in self.handlers],
        }


def detect_vm_dispatcher(blocks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Detect VM dispatcher pattern in a function's basic blocks.

    VM dispatcher signature:
    - A block inside a loop (back-edge to itself or parent)
    - Has many successors (one per opcode handler)
    - Usually accessed via indirect jump or large switch
    - Often the block with the most incoming edges
    """
    if len(blocks) < 5:
        return None

    block_map = {b["addr"]: b for b in blocks}

    # Count incoming edges for each block
    in_edges: dict[int, int] = {b["addr"]: 0 for b in blocks}
    for block in blocks:
        for succ in block.get("succs", []):
            if succ in in_edges:
                in_edges[succ] += 1

    # The dispatcher typically has the most incoming edges
    # and many outgoing edges (handler dispatch)
    best_candidate = None
    best_score = 0

    for block in blocks:
        addr = block["addr"]
        succs = block.get("succs", [])
        in_count = in_edges.get(addr, 0)
        out_count = len(succs)

        # Dispatcher heuristic: high in-degree + high out-degree
        # Handlers jump back to dispatcher, dispatcher dispatches to handlers
        score = in_count * out_count

        # Must have at least 3 successors (minimum viable VM)
        if out_count >= 3 and in_count >= 3 and score > best_score:
            # Check that most successors eventually jump back here (loop)
            back_jumpers = sum(
                1 for s in succs
                if s in block_map and addr in block_map[s].get("succs", [])
            )
            if back_jumpers >= 2:
                best_score = score
                best_candidate = {
                    "dispatcher_addr": addr,
                    "handler_count": out_count,
                    "in_edges": in_count,
                    "handler_addrs": succs,
                }

    return best_candidate


def classify_handler(
    handler_addr: int,
    blocks: list[dict[str, Any]],
    binary_bytes: bytes,
    base_addr: int,
    arch: str = "x86_64",
) -> VMHandler:
    """Classify a VM handler's semantics based on its code pattern.

    Uses Capstone disassembly when binary bytes are available for
    instruction-level classification.  Falls back to heuristic
    block-property analysis when bytes are empty or Capstone is
    unavailable.

    Common handler types:
    - mov: register-to-register move
    - load: load from memory to register
    - store: store from register to memory
    - add/sub/mul/div: arithmetic
    - and/or/xor/not: bitwise
    - cmp: comparison
    - jmp/jz/jnz: control flow
    - call: function call
    - ret: return from VM
    - push/pop: stack operations
    - nop: no operation
    """
    # ---- Disassembly-based classification (preferred) ----
    if binary_bytes and len(binary_bytes) > 0:
        from d810g_engine.virtualization.disasm import classify_handler_by_disasm
        result = classify_handler_by_disasm(
            handler_addr, binary_bytes, base_addr, arch,
        )
        if result.get("confidence") in ("high", "medium"):
            handler = VMHandler(opcode=0, address=handler_addr)
            handler.semantics = result["semantics"]
            handler.operand_count = result.get("operand_count", 0)
            handler.description = result.get("description", "")
            return handler

    # ---- Heuristic fallback ----
    handler = VMHandler(opcode=0, address=handler_addr)

    # Find this handler's block
    handler_block = None
    for b in blocks:
        if b["addr"] == handler_addr:
            handler_block = b
            break

    if handler_block is None:
        handler.semantics = "unknown"
        return handler

    # Analyze instruction count and pattern
    insn_count = handler_block.get("insn_count", 0)
    succs = handler_block.get("succs", [])
    has_memory_access = handler_block.get("has_memory_access", False)
    has_arithmetic = handler_block.get("has_arithmetic", False)
    has_branch = len(succs) > 1

    # Heuristic classification based on block properties
    if insn_count <= 2 and len(succs) == 0:
        handler.semantics = "ret"
        handler.description = "Return from VM execution"
        handler.operand_count = 1
    elif insn_count <= 3 and not has_memory_access and not has_arithmetic:
        handler.semantics = "mov"
        handler.description = "Register move"
        handler.operand_count = 2
    elif insn_count <= 3 and not has_memory_access and has_arithmetic:
        handler.semantics = "add"
        handler.description = "Arithmetic operation"
        handler.operand_count = 2
    elif has_memory_access and not has_arithmetic:
        if insn_count <= 4:
            handler.semantics = "load"
            handler.description = "Load from memory"
            handler.operand_count = 2
        else:
            handler.semantics = "store"
            handler.description = "Store to memory"
            handler.operand_count = 2
    elif has_branch:
        handler.semantics = "branch"
        handler.description = "Conditional branch"
        handler.operand_count = 1
    else:
        handler.semantics = "unknown"
        handler.description = "Unclassified handler"
        handler.operand_count = 0

    return handler


def analyze_vm(params: dict[str, Any]) -> dict[str, Any]:
    """Main entry: detect VM, extract handlers, classify semantics.

    Params:
        blocks: basic block graph
        binary_hex: hex-encoded function bytes
        arch: architecture string
        base_addr: base address of the function
    """
    blocks = params["blocks"]
    binary_bytes = bytes.fromhex(params.get("binary_hex", ""))
    arch = params.get("arch", "x86_64")
    base_addr = params.get("base_addr", 0)

    # Step 1: Detect VM dispatcher
    dispatcher = detect_vm_dispatcher(blocks)

    if dispatcher is None:
        return {
            "status": "no_vm_detected",
            "context": None,
        }

    # Step 2: Build VM context
    ctx = VMContext()
    ctx.dispatcher_addr = dispatcher["dispatcher_addr"]

    # Step 3: Classify each handler
    for handler_addr in dispatcher["handler_addrs"]:
        handler = classify_handler(handler_addr, blocks, binary_bytes, base_addr, arch)
        ctx.handlers.append(handler)

    # Step 4: Assign opcodes (index-based for now)
    for i, handler in enumerate(ctx.handlers):
        handler.opcode = i

    return {
        "status": "vm_detected",
        "dispatcher": dispatcher,
        "context": ctx.to_dict(),
        "summary": (
            f"VM detected at 0x{dispatcher['dispatcher_addr']:x} with "
            f"{len(ctx.handlers)} handlers: "
            + ", ".join(h.semantics for h in ctx.handlers)
        ),
    }
