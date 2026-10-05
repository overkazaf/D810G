import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.deflattener.detector import detect_cff_pattern


def test_detect_switch_dispatch():
    """Detect OLLVM-style switch dispatcher with state variable."""
    blocks = [
        {"addr": 0x1000, "type": "dispatcher", "succs": [0x1010, 0x1020, 0x1030, 0x1040]},
        {"addr": 0x1010, "type": "case", "state_update": 0xAABBCCDD, "succs": [0x1000]},
        {"addr": 0x1020, "type": "case", "state_update": 0x11223344, "succs": [0x1000]},
        {"addr": 0x1030, "type": "case", "state_update": 0x55667788, "succs": [0x1000]},
        {"addr": 0x1040, "type": "return", "succs": []},
    ]
    result = detect_cff_pattern(blocks)
    assert result is not None
    assert result["type"] == "ollvm_switch"
    assert result["dispatcher"] == 0x1000
    assert len(result["case_blocks"]) == 3


def test_no_cff_in_normal_code():
    blocks = [
        {"addr": 0x1000, "type": "entry", "succs": [0x1010]},
        {"addr": 0x1010, "type": "block", "succs": [0x1020, 0x1030]},
        {"addr": 0x1020, "type": "block", "succs": [0x1040]},
        {"addr": 0x1030, "type": "block", "succs": [0x1040]},
        {"addr": 0x1040, "type": "return", "succs": []},
    ]
    result = detect_cff_pattern(blocks)
    assert result is None


def test_deflat_ollvm_no_cff():
    from d810g_engine.deflattener.ollvm import deflat_ollvm
    result = deflat_ollvm({
        "blocks": [
            {"addr": 0x1000, "succs": [0x1010]},
            {"addr": 0x1010, "succs": []},
        ],
        "binary_hex": "c3",
    })
    assert result["status"] == "no_cff_detected"


def test_deflat_ollvm_with_cff():
    from d810g_engine.deflattener.ollvm import deflat_ollvm
    result = deflat_ollvm({
        "blocks": [
            {"addr": 0x1000, "succs": [0x1010, 0x1020, 0x1030, 0x1040]},
            {"addr": 0x1010, "state_update": 0xAA, "succs": [0x1000]},
            {"addr": 0x1020, "state_update": 0xBB, "succs": [0x1000]},
            {"addr": 0x1030, "state_update": 0xCC, "succs": [0x1000]},
            {"addr": 0x1040, "succs": []},
        ],
        "binary_hex": "90" * 100,
    })
    assert result["status"] == "deobfuscated"
    assert result["pattern"]["type"] == "ollvm_switch"


# ---- Symbolic execution tests ----


def test_solve_state_transitions_x86():
    """Emulate a minimal x86_64 case block that writes a state variable."""
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    from d810g_engine.deflattener.symbolic import solve_state_transitions

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # Assemble a case block at 0x401100:
    #   push rbp; mov rbp, rsp
    #   mov dword ptr [rbp-0x10], 0xBBBBBBBB
    #   jmp 0x401000  (back to dispatcher)
    code, _ = ks.asm(
        "push rbp; mov rbp, rsp; "
        "mov dword ptr [rbp-0x10], 0xBBBBBBBB; "
        "jmp 0x401000",
        addr=0x401100,
    )

    # binary_bytes[0] maps to 0x400000; code lands at offset 0x1100
    binary = bytes(0x1100) + bytes(code) + bytes(0x1000)

    transitions = solve_state_transitions(
        binary_bytes=binary,
        arch="x86_64",
        dispatcher_addr=0x401000,
        state_var_offset=0x10,
        state_var_size=4,
        case_blocks=[0x401100],
    )
    assert len(transitions) == 1
    assert transitions[0]["from_block"] == 0x401100
    assert transitions[0]["state_value"] == 0xBBBBBBBB


def test_solve_multiple_blocks():
    """Two case blocks with different state values."""
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    from d810g_engine.deflattener.symbolic import solve_state_transitions

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # Block A at 0x401100: state <- 0x11111111
    code_a, _ = ks.asm(
        "push rbp; mov rbp, rsp; "
        "mov dword ptr [rbp-0x8], 0x11111111; "
        "jmp 0x401000",
        addr=0x401100,
    )
    # Block B at 0x401200: state <- 0x22222222
    code_b, _ = ks.asm(
        "push rbp; mov rbp, rsp; "
        "mov dword ptr [rbp-0x8], 0x22222222; "
        "jmp 0x401000",
        addr=0x401200,
    )

    binary = bytearray(0x2000)
    binary[0x1100 : 0x1100 + len(code_a)] = code_a
    binary[0x1200 : 0x1200 + len(code_b)] = code_b

    transitions = solve_state_transitions(
        binary_bytes=bytes(binary),
        arch="x86_64",
        dispatcher_addr=0x401000,
        state_var_offset=0x8,
        state_var_size=4,
        case_blocks=[0x401100, 0x401200],
        base_address=0x400000,
    )
    assert len(transitions) == 2

    vals = {t["from_block"]: t["state_value"] for t in transitions}
    assert vals[0x401100] == 0x11111111
    assert vals[0x401200] == 0x22222222


def test_solve_no_state_write():
    """A block that does not write the state variable yields None."""
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    from d810g_engine.deflattener.symbolic import solve_state_transitions

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # nop; nop; jmp dispatcher  (no state assignment)
    code, _ = ks.asm("nop; nop; jmp 0x401000", addr=0x401100)
    binary = bytearray(0x2000)
    binary[0x1100 : 0x1100 + len(code)] = code

    transitions = solve_state_transitions(
        binary_bytes=bytes(binary),
        arch="x86_64",
        dispatcher_addr=0x401000,
        state_var_offset=0x10,
        state_var_size=4,
        case_blocks=[0x401100],
        base_address=0x400000,
    )
    assert len(transitions) == 1
    assert transitions[0]["state_value"] is None


def test_patch_control_flow_x86():
    """Patch generation produces valid entries for each transition."""
    from d810g_engine.deflattener.symbolic import patch_control_flow

    transitions = [
        {"from_block": 0x401100, "to_block": 0x401200, "state_value": 0xBB},
        {"from_block": 0x401200, "to_block": 0x401300, "state_value": 0xCC},
    ]
    patches = patch_control_flow(
        binary_bytes=bytearray(b"\x90" * 0x2000),
        arch="x86_64",
        transitions=transitions,
        dispatcher_addr=0x401000,
    )
    assert len(patches) >= 1
    for p in patches:
        assert "address" in p
        assert "patch_bytes" in p
        assert "original_bytes" in p


def test_patch_with_real_code():
    """Patch replaces a state assignment + jmp with a direct jump + NOPs."""
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    from d810g_engine.deflattener.symbolic import patch_control_flow

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # mov dword ptr [rbp-0x10], 0xCC; jmp 0x401000
    code, _ = ks.asm(
        "mov dword ptr [rbp-0x10], 0xCC; jmp 0x401000",
        addr=0x401100,
    )

    binary = bytearray(b"\x90" * 0x2000)
    binary[0x1100 : 0x1100 + len(code)] = code

    transitions = [
        {"from_block": 0x401100, "to_block": 0x401200, "state_value": 0xCC},
    ]
    patches = patch_control_flow(
        binary_bytes=binary,
        arch="x86_64",
        transitions=transitions,
        dispatcher_addr=0x401000,
        base_address=0x400000,
        state_var_offset=0x10,
    )
    assert len(patches) == 1
    p = patches[0]
    assert p["address"] == 0x401100  # patch starts at the state assignment
    assert p["patch_bytes"][0:1] == b"\xe9"  # x86 jmp rel32 opcode
    assert len(p["patch_bytes"]) == len(p["original_bytes"])  # size preserved


def test_patch_skips_no_target():
    """Transitions with to_block=None produce no patches."""
    from d810g_engine.deflattener.symbolic import patch_control_flow

    transitions = [
        {"from_block": 0x401100, "to_block": None, "state_value": 0xAA},
    ]
    patches = patch_control_flow(
        binary_bytes=bytearray(b"\x90" * 0x2000),
        arch="x86_64",
        transitions=transitions,
        dispatcher_addr=0x401000,
    )
    assert len(patches) == 0
