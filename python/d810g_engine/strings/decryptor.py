"""Detect and decrypt OLLVM-encrypted strings."""

from __future__ import annotations
from typing import Any


def find_encrypted_strings(
    binary_bytes: bytes,
    sections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Find potential encrypted string regions in the binary.

    Heuristics:
    - Located in .data or .rodata sections
    - High entropy (random-looking bytes)
    - Followed by or near a null terminator pattern
    - Referenced by code that looks like a decryption loop
    """
    candidates = []

    for section in sections:
        if section["name"] not in (".data", ".rodata", ".bss"):
            continue

        start = section["offset"]
        end = start + section["size"]
        if end > len(binary_bytes):
            end = len(binary_bytes)

        data = binary_bytes[start:end]

        # Scan for high-entropy regions that could be encrypted strings
        window_size = 8
        i = 0
        while i < len(data) - window_size:
            window = data[i:i + window_size]

            # Skip null regions
            if all(b == 0 for b in window):
                i += window_size
                continue

            # Check entropy: encrypted data should have relatively uniform byte distribution
            entropy = _byte_entropy(window)
            if entropy > 3.5:  # threshold for "looks encrypted"
                # Find the extent of this region (until null terminator or low-entropy region)
                region_end = i + window_size
                while region_end < len(data) and data[region_end] != 0:
                    region_end += 1

                region_len = region_end - i
                if 4 <= region_len <= 4096:  # reasonable string length
                    candidates.append({
                        "section": section["name"],
                        "offset": section["vaddr"] + i,
                        "size": region_len,
                        "data": data[i:region_end].hex(),
                        "entropy": round(entropy, 2),
                    })

                i = region_end + 1
            else:
                i += 1

    return candidates


def try_xor_decrypt(
    encrypted_hex: str,
    key_candidates: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Try to decrypt data using XOR with various key patterns.

    Tries:
    1. Single-byte XOR keys (0x01-0xFF)
    2. User-provided key candidates
    3. XOR with index (key ^ i)
    """
    encrypted = bytes.fromhex(encrypted_hex)
    results = []

    if key_candidates is None:
        key_candidates = list(range(1, 256))

    for key in key_candidates:
        # Single-byte XOR
        decrypted = bytes(b ^ key for b in encrypted)
        score = _printable_score(decrypted)
        if score > 0.7:
            try:
                text = decrypted.decode("utf-8", errors="strict")
                results.append({
                    "method": "xor_single",
                    "key": key,
                    "key_hex": f"0x{key:02x}",
                    "decrypted": text,
                    "score": round(score, 3),
                })
            except UnicodeDecodeError:
                pass

        # XOR with index
        decrypted_idx = bytes((b ^ (key ^ (i % 256))) for i, b in enumerate(encrypted))
        score_idx = _printable_score(decrypted_idx)
        if score_idx > 0.7:
            try:
                text = decrypted_idx.decode("utf-8", errors="strict")
                results.append({
                    "method": "xor_index",
                    "key": key,
                    "key_hex": f"0x{key:02x}",
                    "decrypted": text,
                    "score": round(score_idx, 3),
                })
            except UnicodeDecodeError:
                pass

    # Sort by score descending, then prefer alphabetic-heavy decryptions
    results.sort(key=lambda r: (r["score"], _alpha_ratio(r["decrypted"])), reverse=True)
    return results


def decrypt_strings(params: dict[str, Any]) -> dict[str, Any]:
    """Main entry: find and decrypt OLLVM-encrypted strings.

    Params:
        binary_hex: hex-encoded binary data
        sections: list of {name, offset, vaddr, size} section descriptors
        key: optional known encryption key
        addresses: optional list of specific addresses to try decrypting
    """
    binary_bytes = bytes.fromhex(params["binary_hex"])
    sections = params.get("sections", [])
    known_key = params.get("key")
    target_addrs = params.get("addresses")

    # If specific addresses provided, try to decrypt those
    if target_addrs:
        results = []
        for addr_info in target_addrs:
            data_hex = addr_info["data_hex"]
            key_candidates = [known_key] if known_key else None
            decryptions = try_xor_decrypt(data_hex, key_candidates)
            if decryptions:
                results.append({
                    "address": addr_info["address"],
                    "decryptions": decryptions,
                })
        return {
            "status": "decrypted" if results else "no_results",
            "results": results,
        }

    # Otherwise, scan for encrypted strings
    candidates = find_encrypted_strings(binary_bytes, sections)

    results = []
    for candidate in candidates:
        key_candidates = [known_key] if known_key else None
        decryptions = try_xor_decrypt(candidate["data"], key_candidates)
        if decryptions:
            results.append({
                "address": candidate["offset"],
                "section": candidate["section"],
                "original_size": candidate["size"],
                "entropy": candidate["entropy"],
                "decryptions": decryptions,
            })

    return {
        "status": "decrypted" if results else "no_encrypted_strings",
        "candidates_scanned": len(candidates),
        "results": results,
    }


def _byte_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def _printable_score(data: bytes) -> float:
    """Score how printable a byte sequence is (0.0 to 1.0)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
    return printable / len(data)


def _alpha_ratio(text: str) -> float:
    """Ratio of alphanumeric characters -- higher means more likely real text."""
    if not text:
        return 0.0
    return sum(1 for c in text if c.isalnum()) / len(text)
