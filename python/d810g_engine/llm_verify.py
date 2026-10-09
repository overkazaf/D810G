"""Formal check of LLM-proposed deobfuscation results.

"Deconstructing Obfuscation" (arXiv:2505.19887) shows LLM deobfuscators make
arithmetic slips and invent constants (hexspeak like 0xDEADBEEF, or values
such as 0xe6c98769 that appear nowhere in the binary).  This module proves a
candidate equivalent to the obfuscated expression with Z3 at each requested
bit width -- or returns a concrete counterexample -- and flags candidate
constants that cannot be traced back to the original or the binary.
"""

from __future__ import annotations

from typing import Any, Iterable

from d810g_engine.mba.verifier import prove_equivalence
from d810g_engine.parser import _tokenize

# Well-known "magic" words LLMs reach for when they make a constant up.
HEXSPEAK = frozenset({
    0xDEADBEEF, 0xCAFEBABE, 0xBAADF00D, 0xDEADC0DE, 0xFEEDFACE, 0x8BADF00D,
    0xC0FFEE, 0xDEADBABE, 0xBADC0DE, 0xFACEFEED, 0xCAFED00D, 0xDEADFA11,
    0xFEE1DEAD, 0x1BADB002, 0xDEADDEAD, 0xBADDCAFE, 0xCAFEF00D, 0xABADBABE,
    0xD15EA5E, 0xFEEDC0DE, 0xC0DEBA5E, 0x0DEFACED, 0xBEEFCAFE, 0x12345678,
})


def extract_constants(expr: str) -> list[int]:
    """Integer literals in *expr*, in order of first appearance."""
    seen: list[int] = []
    for tok in _tokenize(expr):
        if tok[0].isdigit():
            val = int(tok, 16) if tok[:2] in ("0x", "0X") else int(tok)
            if val not in seen:
                seen.append(val)
    return seen


def _is_trivial(val: int, mask: int) -> bool:
    """Small literals, powers of two and low-bit masks need no provenance."""
    val &= mask
    for v in (val, (-val) & mask):
        if v <= 0xFF or v & (v - 1) == 0 or v & (v + 1) == 0:
            return True
    return False


def _derivable(val: int, known: Iterable[int], mask: int) -> bool:
    """*val* equals some known constant, its complement or its negation."""
    val &= mask
    return any(val in (k & mask, ~k & mask, -k & mask) for k in known)


def find_suspicious_constants(
    original: str,
    candidate: str,
    known_constants: Iterable[int] = (),
    bit_widths: Iterable[int] = (32, 64),
) -> list[dict[str, Any]]:
    """Candidate constants absent from the original / known set."""
    known = set(extract_constants(original)) | set(known_constants)
    masks = [(1 << w) - 1 for w in bit_widths]
    flagged = []
    for val in extract_constants(candidate):
        if any(_is_trivial(val, m) or _derivable(val, known, m) for m in masks):
            continue
        hexspeak = val in HEXSPEAK
        flagged.append({
            "value": val,
            "hex": hex(val),
            "hexspeak": hexspeak,
            "reason": ("well-known hexspeak constant, likely fabricated" if hexspeak
                       else "not present in original expression or known constants"),
        })
    return flagged


def verify_llm_output(
    original: str,
    candidate: str,
    bit_widths: Iterable[int] = (32, 64),
    known_constants: Iterable[int] = (),
    signed: bool = True,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    """Prove *candidate* equivalent to *original* and audit its constants.

    ``equivalent`` is True only if every width is proven equivalent; an
    ``unknown`` (solver timeout) width counts as not verified.
    """
    bit_widths = list(bit_widths)
    result: dict[str, Any] = {"original": original, "candidate": candidate, "widths": {}}

    for bits in bit_widths:
        res = prove_equivalence(original, candidate, bit_width=bits,
                                signed=signed, timeout_ms=timeout_ms)
        result["widths"][str(bits)] = res
        if res["result"] == "error":
            result["error"] = res["error"]
            break

    result["equivalent"] = bool(result["widths"]) and all(
        w["result"] == "equivalent" for w in result["widths"].values())

    try:
        result["candidate_constants"] = extract_constants(candidate)
        result["suspicious_constants"] = find_suspicious_constants(
            original, candidate, known_constants, bit_widths)
    except ValueError as e:
        result["candidate_constants"] = []
        result["suspicious_constants"] = []
        result.setdefault("error", f"parse error: {e}")
    return result


def register_handlers(server: Any) -> None:
    """Register the LLM output verifier on the server."""
    server.register("verify.llm_output", lambda p: verify_llm_output(**p))
