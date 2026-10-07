"""Recover state transitions using unicorn-based emulation.

Uses Unicorn to emulate each case block in an OLLVM-flattened function,
determines the state-variable value each block assigns, and generates binary
patches that replace the state-machine dispatch loop with direct jumps.
"""

from __future__ import annotations

import re
from typing import Any

from d810g_engine.log import get_logger

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MODE_64,
    UC_MODE_ARM,
)
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R11
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X29
from unicorn.x86_const import UC_X86_REG_RBP, UC_X86_REG_RSP
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_ARM
from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_X86, KS_MODE_64, KS_MODE_ARM as KS_MODE_ARM32, KS_MODE_LITTLE_ENDIAN

log = get_logger("deflattener.symbolic")

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
_MAX_INSNS = 200  # max instructions per emulation run
_TIMEOUT_US = 5_000_000  # 5 seconds
_STACK_BASE = 0x7FFF_0000
_STACK_SIZE = 0x0001_0000
_INIT_SP = _STACK_BASE + _STACK_SIZE - 0x1000
_SCAN_BYTES = 128  # bytes to disassemble when scanning a case block

_ARCH_X86_64 = "x86_64"
_ARCH_ARM64 = "arm64"
_ARCH_ARM32 = "arm"


# ---------------------------------------------------------------------------
# Architecture configuration
# ---------------------------------------------------------------------------

def _arch_cfg(arch: str) -> dict[str, Any]:
    """Return a config dict covering Unicorn, Capstone, and Keystone."""
    a = arch.lower()
    if any(k in a for k in ("x86", "x64", "amd64")):
        return dict(
            uc_arch=UC_ARCH_X86, uc_mode=UC_MODE_64,
            cs_arch=CS_ARCH_X86, cs_mode=CS_MODE_64,
            ks_arch=KS_ARCH_X86, ks_mode=KS_MODE_64,
            sp_reg=UC_X86_REG_RSP, bp_reg=UC_X86_REG_RBP,
            nop=b"\x90", jmp_size=5, name=_ARCH_X86_64,
        )
    if any(k in a for k in ("aarch64", "arm64")):
        return dict(
            uc_arch=UC_ARCH_ARM64, uc_mode=UC_MODE_ARM,
            cs_arch=CS_ARCH_ARM64, cs_mode=CS_MODE_ARM,
            ks_arch=KS_ARCH_ARM64, ks_mode=KS_MODE_LITTLE_ENDIAN,
            sp_reg=UC_ARM64_REG_SP, bp_reg=UC_ARM64_REG_X29,
            nop=b"\x1f\x20\x03\xd5", jmp_size=4, name=_ARCH_ARM64,
        )
    if "arm" in a:
        return dict(
            uc_arch=UC_ARCH_ARM, uc_mode=UC_MODE_ARM,
            cs_arch=CS_ARCH_ARM, cs_mode=CS_MODE_ARM,
            ks_arch=KS_ARCH_ARM, ks_mode=KS_MODE_ARM32,
            sp_reg=UC_ARM_REG_SP, bp_reg=UC_ARM_REG_R11,
            nop=b"\x00\x00\xa0\xe1", jmp_size=4, name=_ARCH_ARM32,
        )
    raise ValueError(f"Unsupported architecture: {arch}")


# ---------------------------------------------------------------------------
# Image-base inference
# ---------------------------------------------------------------------------

def _infer_base(binary_len: int, addrs: list[int]) -> int:
    """Heuristic: find a page-aligned image base so every address in *addrs*
    is a valid offset into a binary of *binary_len* bytes."""
    if not addrs or binary_len == 0:
        return 0
    # Try well-known ELF / PE image bases.
    for base in (0x0040_0000, 0x0010_0000, 0x0001_0000, 0x0804_8000, 0):
        if all(0 <= a - base < binary_len for a in addrs):
            return base
    lo = min(addrs)
    # Fall back to 64K- or 4K-aligned minimum address.
    for base in (lo & ~0xFFFF, lo & ~0xFFF):
        if all(0 <= a - base < binary_len for a in addrs):
            return base
    return lo & ~0xFFF


# ---------------------------------------------------------------------------
# Unicorn memory helpers
# ---------------------------------------------------------------------------

def _map_binary(uc: Uc, data: bytes, base: int) -> None:
    """Map *data* into Unicorn at *base* (page-aligned)."""
    page_base = base & ~0xFFF
    page_end = ((base + len(data)) + 0xFFF) & ~0xFFF
    uc.mem_map(page_base, max(page_end - page_base, 0x1000))
    uc.mem_write(base, data)


def _init_stack(uc: Uc, cfg: dict) -> int:
    """Map stack memory and set SP / BP.  Returns the initial SP value."""
    uc.mem_map(_STACK_BASE, _STACK_SIZE)
    uc.reg_write(cfg["sp_reg"], _INIT_SP)
    uc.reg_write(cfg["bp_reg"], _INIT_SP)
    return _INIT_SP


def _stop_on_unmapped(_uc, _access, _addr, _size, _val, _ud):
    """Hook callback: stop emulation on any unmapped memory access."""
    return False


_UNMAPPED_HOOKS = (
    UC_HOOK_MEM_READ_UNMAPPED
    | UC_HOOK_MEM_WRITE_UNMAPPED
    | UC_HOOK_MEM_FETCH_UNMAPPED
)


# ---------------------------------------------------------------------------
# Phase 1 -- emulate each case block to discover state-variable writes
# ---------------------------------------------------------------------------

def _emulate_case_block(
    binary: bytes,
    cfg: dict,
    base: int,
    block_addr: int,
    dispatcher_addr: int,
    sv_offset: int,
    sv_size: int,
) -> int | None:
    """Run a single case block and return the value it writes to the
    state variable, or ``None`` if no write was detected."""
    uc = Uc(cfg["uc_arch"], cfg["uc_mode"])
    _map_binary(uc, binary, base)
    _init_stack(uc, cfg)

    writes: list[int] = []
    bp_reg = cfg["bp_reg"]
    mask = (1 << (sv_size * 8)) - 1

    # Hook every memory write; keep only those targeting [BP - sv_offset].
    def on_mem_write(_uc, _access, address, size, value, _ud):
        bp = _uc.reg_read(bp_reg)
        if address == (bp - sv_offset) and size == sv_size:
            writes.append(value & mask)

    uc.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)
    uc.hook_add(_UNMAPPED_HOOKS, _stop_on_unmapped)

    try:
        uc.emu_start(
            block_addr, dispatcher_addr,
            timeout=_TIMEOUT_US, count=_MAX_INSNS,
        )
    except UcError as exc:
        log.debug("Block 0x%x emulation error: %s", block_addr, exc)

    return writes[-1] if writes else None


# ---------------------------------------------------------------------------
# Phase 2 -- resolve state values to target blocks via dispatcher emulation
# ---------------------------------------------------------------------------

def _resolve_targets(
    transitions: list[dict],
    binary: bytes,
    cfg: dict,
    base: int,
    dispatcher_addr: int,
    sv_offset: int,
    sv_size: int,
    case_set: set[int],
) -> None:
    """Mutate *transitions* in-place: for each entry whose state_value is
    known, emulate the dispatcher with that value set and record which
    case-block address execution reaches first."""
    for tr in transitions:
        sv = tr["state_value"]
        if sv is None:
            continue

        uc = Uc(cfg["uc_arch"], cfg["uc_mode"])
        try:
            _map_binary(uc, binary, base)
        except UcError:
            continue
        sp = _init_stack(uc, cfg)

        # Place the state value at the expected stack location.
        state_addr = sp - sv_offset
        try:
            uc.mem_write(state_addr, sv.to_bytes(sv_size, "little"))
        except (UcError, OverflowError):
            continue

        hit: list[int | None] = [None]
        insn_count: list[int] = [0]

        def on_code(_uc, address, _size, _ud):
            insn_count[0] += 1
            if address != dispatcher_addr and address in case_set:
                hit[0] = address
                _uc.emu_stop()
            if insn_count[0] > _MAX_INSNS:
                _uc.emu_stop()

        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.hook_add(_UNMAPPED_HOOKS, _stop_on_unmapped)

        try:
            uc.emu_start(
                dispatcher_addr, 0,
                timeout=_TIMEOUT_US, count=_MAX_INSNS,
            )
        except UcError:
            pass

        if hit[0] is not None:
            tr["to_block"] = hit[0]


# ---------------------------------------------------------------------------
# Public: solve_state_transitions
# ---------------------------------------------------------------------------

def solve_state_transitions(
    binary_bytes: bytes,
    arch: str,
    dispatcher_addr: int,
    state_var_offset: int,
    state_var_size: int,
    case_blocks: list[int],
    *,
    base_address: int | None = None,
) -> list[dict[str, Any]]:
    """Determine the original control flow by emulating each case block.

    Parameters
    ----------
    binary_bytes : bytes
        Raw image bytes.  ``binary_bytes[0]`` corresponds to virtual address
        *base_address*.
    arch : str
        ``"x86_64"``, ``"arm64"``, or ``"arm"`` (ARM32).
    dispatcher_addr : int
        Virtual address of the CFF dispatcher block.
    state_var_offset : int
        Positive offset of the state variable below the frame pointer
        (``[rbp - offset]`` on x86_64, ``[x29 - offset]`` on ARM64,
        ``[r11, #-offset]`` on ARM32).
    state_var_size : int
        Width of the state variable in bytes (typically 4).
    case_blocks : list[int]
        Virtual addresses of the case (body) blocks.
    base_address : int, optional
        Virtual address that ``binary_bytes[0]`` maps to.  Inferred
        automatically when omitted.

    Returns
    -------
    list[dict]
        ``[{"from_block": int, "state_value": int | None,
             "to_block": int | None}, ...]``
    """
    if not binary_bytes or not case_blocks:
        return [
            dict(from_block=b, state_value=None, to_block=None)
            for b in case_blocks
        ]

    cfg = _arch_cfg(arch)
    all_addrs = [dispatcher_addr, *case_blocks]
    if base_address is None:
        base_address = _infer_base(len(binary_bytes), all_addrs)

    transitions: list[dict[str, Any]] = []
    for blk in case_blocks:
        val = _emulate_case_block(
            binary_bytes, cfg, base_address,
            blk, dispatcher_addr, state_var_offset, state_var_size,
        )
        transitions.append(dict(from_block=blk, state_value=val, to_block=None))

    # Phase 2: resolve each state_value to the case block it selects.
    _resolve_targets(
        transitions, binary_bytes, cfg, base_address,
        dispatcher_addr, state_var_offset, state_var_size,
        set(case_blocks),
    )
    return transitions


# ---------------------------------------------------------------------------
# Instruction-level helpers for patch generation
# ---------------------------------------------------------------------------

def _is_state_assign(insn, arch_name: str, sv_offset: int) -> bool:
    """Return True if *insn* writes to ``[bp - sv_offset]``."""
    if arch_name == _ARCH_X86_64 and insn.mnemonic == "mov":
        pat = r"\[rbp\s*-\s*0x" + format(sv_offset, "x") + r"\]"
        return bool(re.search(pat, insn.op_str, re.IGNORECASE))
    if arch_name == _ARCH_ARM64 and insn.mnemonic in ("str", "stur"):
        pat = r"x29,\s*#?\s*-?\s*0x" + format(sv_offset, "x")
        return bool(re.search(pat, insn.op_str, re.IGNORECASE))
    if arch_name == _ARCH_ARM32 and insn.mnemonic == "str":
        pat = r"r11,\s*#?\s*-?\s*0x" + format(sv_offset, "x")
        return bool(re.search(pat, insn.op_str, re.IGNORECASE))
    return False


def _jump_target(insn, arch_name: str) -> int | None:
    """Return the absolute target of a direct unconditional jump, or None."""
    if arch_name == _ARCH_X86_64 and insn.mnemonic == "jmp":
        try:
            return int(insn.op_str, 0)
        except ValueError:
            return None
    if arch_name in (_ARCH_ARM64, _ARCH_ARM32) and insn.mnemonic == "b":
        raw = insn.op_str.lstrip("#").strip()
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Patch builder
# ---------------------------------------------------------------------------

def _make_patch(
    binary: bytearray,
    cfg: dict,
    ks: Ks,
    cs: Cs,
    base: int,
    from_block: int,
    to_block: int,
    dispatcher_addr: int,
    sv_offset: int,
) -> dict[str, Any] | None:
    """Build a single patch replacing the state-assign + dispatcher back-jump
    in *from_block* with a direct jump to *to_block*."""
    off = from_block - base
    scan = min(_SCAN_BYTES, len(binary) - off)
    if scan <= 0:
        return None

    code = bytes(binary[off : off + scan])

    assign_addr: int | None = None
    jmp_addr: int | None = None
    jmp_end: int | None = None

    for insn in cs.disasm(code, from_block):
        if sv_offset and _is_state_assign(insn, cfg["name"], sv_offset):
            assign_addr = insn.address
        tgt = _jump_target(insn, cfg["name"])
        if tgt == dispatcher_addr:
            jmp_addr = insn.address
            jmp_end = insn.address + insn.size

    # Determine the patch region.
    if assign_addr is not None and jmp_end is not None:
        patch_start = assign_addr
        patch_len = jmp_end - assign_addr
    elif jmp_addr is not None and jmp_end is not None:
        patch_start = jmp_addr
        patch_len = jmp_end - jmp_addr
    else:
        # Fallback: emit a direct jump at the block start.
        patch_start = from_block
        patch_len = cfg["jmp_size"]

    # Assemble the replacement jump.
    if cfg["name"] == _ARCH_X86_64:
        asm_str = f"jmp 0x{to_block:x}"
    else:
        asm_str = f"b 0x{to_block:x}"

    try:
        enc, _ = ks.asm(asm_str, addr=patch_start)
        jmp_bytes = bytes(enc)
    except Exception as exc:  # noqa: BLE001
        log.warning("Keystone asm error at 0x%x: %s", patch_start, exc)
        return None

    # Pad the remaining bytes with NOPs.
    nop = cfg["nop"]
    pad_needed = max(0, patch_len - len(jmp_bytes))
    nop_pad = (nop * (pad_needed // len(nop) + 1))[:pad_needed]

    p_off = patch_start - base
    original = bytes(binary[p_off : p_off + patch_len])

    return dict(
        address=patch_start,
        original_bytes=original,
        patch_bytes=jmp_bytes + nop_pad,
    )


# ---------------------------------------------------------------------------
# Public: patch_control_flow
# ---------------------------------------------------------------------------

def patch_control_flow(
    binary_bytes: bytearray,
    arch: str,
    transitions: list[dict[str, Any]],
    dispatcher_addr: int,
    *,
    base_address: int | None = None,
    state_var_offset: int = 0,
) -> list[dict[str, Any]]:
    """Generate binary patches to restore direct control flow.

    For each transition whose *to_block* is resolved, the state-variable
    assignment and the jump back to the dispatcher are replaced by a single
    ``jmp to_block`` (x86_64) or ``b to_block`` (ARM64/ARM32), padded with NOPs.

    Returns
    -------
    list[dict]
        ``[{"address": int, "original_bytes": bytes,
             "patch_bytes": bytes}, ...]``
    """
    if not transitions:
        return []

    cfg = _arch_cfg(arch)

    all_addrs = [dispatcher_addr]
    all_addrs += [t["from_block"] for t in transitions]
    all_addrs += [t["to_block"] for t in transitions if t.get("to_block")]
    if base_address is None:
        base_address = _infer_base(len(binary_bytes), all_addrs)

    ks = Ks(cfg["ks_arch"], cfg["ks_mode"])
    cs = Cs(cfg["cs_arch"], cfg["cs_mode"])
    cs.detail = True

    patches: list[dict[str, Any]] = []
    for tr in transitions:
        to_block = tr.get("to_block")
        if to_block is None:
            continue
        patch = _make_patch(
            binary_bytes, cfg, ks, cs, base_address,
            tr["from_block"], to_block, dispatcher_addr, state_var_offset,
        )
        if patch is not None:
            patches.append(patch)
    return patches
