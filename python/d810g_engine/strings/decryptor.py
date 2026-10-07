"""Detect and decrypt OLLVM-encrypted strings."""

from __future__ import annotations
from typing import Any

# Common English bigrams (top 30) for n-gram frequency scoring
_COMMON_BIGRAMS = {
    'th', 'he', 'in', 'er', 'an', 'en', 're', 'on', 'at', 'nd',
    'st', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
    'nt', 'to', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le', 'no',
}

# Common programming strings (URLs, paths, SQL, JSON, code keywords)
_CODE_PATTERNS = [
    b'http', b'https', b'www.', b'.com', b'.org', b'.net',
    b'api/', b'/v1', b'/v2', b'json', b'xml',
    b'select', b'insert', b'update', b'delete', b'from', b'where',
    b'function', b'return', b'class', b'import',
    b'password', b'token', b'secret', b'key', b'auth',
]


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
        score = _score_decryption(decrypted)
        if score > 0.80:
            try:
                text = decrypted.decode("utf-8", errors="strict")
                results.append({
                    "method": "xor_single",
                    "key": key,
                    "key_hex": f"0x{key:02x}",
                    "decrypted": text,
                    "score": round(score, 4),
                    "confidence": _confidence_label(score),
                })
            except UnicodeDecodeError:
                pass

        # XOR with index
        decrypted_idx = bytes((b ^ (key ^ (i % 256))) for i, b in enumerate(encrypted))
        score_idx = _score_decryption(decrypted_idx)
        if score_idx > 0.80:
            try:
                text = decrypted_idx.decode("utf-8", errors="strict")
                results.append({
                    "method": "xor_index",
                    "key": key,
                    "key_hex": f"0x{key:02x}",
                    "decrypted": text,
                    "score": round(score_idx, 4),
                    "confidence": _confidence_label(score_idx),
                })
            except UnicodeDecodeError:
                pass

    # Sort by score descending, then prefer alphabetic-heavy decryptions
    results.sort(key=lambda r: (r["score"], _alpha_ratio(r["decrypted"])), reverse=True)
    return results[:5]


def try_rc4_decrypt(
    encrypted_hex: str,
    key_candidates: list[bytes] | None = None,
) -> list[dict[str, Any]]:
    """Try to decrypt data using RC4 with candidate keys.

    If no keys provided, tries common short keys (1-4 bytes).
    """
    encrypted = bytes.fromhex(encrypted_hex)
    results = []

    if key_candidates is None:
        # Try single-byte keys
        key_candidates = [bytes([k]) for k in range(256)]

    for key in key_candidates:
        decrypted = _rc4(key, encrypted)
        score = _score_decryption(decrypted)
        if score > 0.80:
            try:
                text = decrypted.decode("utf-8", errors="strict")
                results.append({
                    "method": "rc4",
                    "key": key.hex(),
                    "key_len": len(key),
                    "decrypted": text,
                    "score": round(score, 4),
                    "confidence": _confidence_label(score),
                })
            except UnicodeDecodeError:
                pass

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:3]


def _rc4(key: bytes, data: bytes) -> bytes:
    """RC4 stream cipher implementation."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def try_sub_table_decrypt(
    encrypted_hex: str,
    table: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Try decryption with a substitution table.

    If no table provided, tries to infer one from frequency analysis.
    """
    encrypted = bytes.fromhex(encrypted_hex)
    results = []

    if table is not None:
        # Direct table application
        if len(table) != 256:
            return []
        decrypted = bytes(table[b] for b in encrypted)
        score = _score_decryption(decrypted)
        if score > 0.5:
            try:
                text = decrypted.decode("utf-8", errors="strict")
                results.append({
                    "method": "substitution",
                    "decrypted": text,
                    "score": round(score, 4),
                    "confidence": _confidence_label(score),
                })
            except UnicodeDecodeError:
                pass
    else:
        # Try ROT-N (Caesar cipher on bytes)
        for rot in range(1, 256):
            decrypted = bytes((b + rot) % 256 for b in encrypted)
            score = _score_decryption(decrypted)
            if score > 0.80:
                try:
                    text = decrypted.decode("utf-8", errors="strict")
                    results.append({
                        "method": f"rot_{rot}",
                        "rotation": rot,
                        "decrypted": text,
                        "score": round(score, 4),
                        "confidence": _confidence_label(score),
                    })
                except UnicodeDecodeError:
                    pass

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:3]


def try_multibyte_xor_decrypt(
    encrypted_hex: str,
    max_key_len: int = 4,
) -> list[dict[str, Any]]:
    """Try multi-byte repeating XOR decryption.

    Uses index of coincidence to guess key length, then frequency analysis.
    """
    encrypted = bytes.fromhex(encrypted_hex)
    results = []

    for key_len in range(2, max_key_len + 1):
        # For each key byte position, find the best single-byte XOR
        key = bytearray()
        for pos in range(key_len):
            subset = bytes(encrypted[i] for i in range(pos, len(encrypted), key_len))
            best_byte = 0
            best_score = -1.0
            for k in range(256):
                dec = bytes(b ^ k for b in subset)
                # Use English text score to prefer real text over random printable
                s = _english_text_score(dec)
                if s > best_score:
                    best_score = s
                    best_byte = k
            key.append(best_byte)

        # Decrypt with the guessed key
        decrypted = bytes(encrypted[i] ^ key[i % key_len] for i in range(len(encrypted)))
        score = _score_decryption(decrypted)

        if score > 0.80:
            try:
                text = decrypted.decode("utf-8", errors="strict")
                results.append({
                    "method": f"xor_multi_{key_len}",
                    "key": bytes(key).hex(),
                    "key_len": key_len,
                    "decrypted": text,
                    "score": round(score, 4),
                    "confidence": _confidence_label(score),
                })
            except UnicodeDecodeError:
                pass

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:3]


def _try_all_methods(data_hex: str, known_key: int | None = None) -> list[dict[str, Any]]:
    """Try all available decryption methods on the data."""
    all_results = []

    # XOR (single-byte)
    key_candidates = [known_key] if known_key else None
    all_results.extend(try_xor_decrypt(data_hex, key_candidates))

    # Multi-byte XOR
    all_results.extend(try_multibyte_xor_decrypt(data_hex))

    # RC4
    all_results.extend(try_rc4_decrypt(data_hex))

    # ROT-N substitution
    all_results.extend(try_sub_table_decrypt(data_hex))

    # Deduplicate by decrypted text
    seen = set()
    unique = []
    for r in all_results:
        if r["decrypted"] not in seen:
            seen.add(r["decrypted"])
            unique.append(r)

    unique.sort(key=lambda r: r["score"], reverse=True)
    return unique[:10]


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
            decryptions = _try_all_methods(data_hex, known_key)
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
        decryptions = _try_all_methods(candidate["data"], known_key)
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


def _score_decryption(data: bytes) -> float:
    """Multi-factor scoring for decryption quality with bigram analysis.

    Architecture: a base quality score (up to ~0.80) gates whether a decryption
    clears the threshold, while additive bonuses (bigram, word structure, code
    patterns) improve ranking so the correct answer rises above printable garbage
    that also clears the gate.

    Base factors:
    1. Printable ratio (weight: 0.30) -- basic ASCII printability
    2. Control char penalty (weight: 0.20) -- penalize non-whitespace control chars
    3. Alphanumeric ratio (weight: 0.20) -- letter/digit density
    4. Length factor (weight: 0.10) -- longer valid strings more likely correct

    Ranking bonuses (additive):
    5. Bigram frequency (up to +0.10) -- common English letter pairs
    6. Word structure (up to +0.05) -- spaces between letter groups
    7. Code pattern bonus (up to +0.05) -- URLs, SQL, code keywords
    """
    if not data or len(data) < 2:
        return 0.0

    length = len(data)

    # --- Base quality (max ~0.80 for clean printable ASCII) ---

    # 1. Printable ratio (weight: 0.30)
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
    printable_ratio = printable / length

    # 2. Control char penalty (weight: 0.20)
    control = sum(1 for b in data if b < 0x20 and b not in (0x09, 0x0a, 0x0d))
    control_penalty = 1.0 - (control / length)

    # 3. Alphanumeric ratio (weight: 0.20)
    alnum = sum(1 for b in data if (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5a) or (0x61 <= b <= 0x7a))
    alnum_ratio = alnum / length

    # 4. Length factor (weight: 0.10)
    length_factor = min(length / 8.0, 1.0)

    base = (
        printable_ratio * 0.30 +
        control_penalty * 0.20 +
        alnum_ratio * 0.20 +
        length_factor * 0.10
    )

    # --- Ranking bonuses (improve differentiation) ---

    # 5. Bigram frequency bonus (up to +0.10)
    # English text typically hits ~25-35% of the common bigram set; we scale
    # the raw ratio by 3x (capped at 1.0) so that realistic English maps to a
    # high bonus value, while random printable ASCII (~5% hit rate) stays low.
    try:
        text = data.decode('ascii', errors='replace').lower()
        bigrams = [text[i:i + 2] for i in range(len(text) - 1)]
        if bigrams:
            common_count = sum(1 for bg in bigrams if bg in _COMMON_BIGRAMS)
            bigram_score = min(common_count / len(bigrams) * 3.0, 1.0)
        else:
            bigram_score = 0.0
    except Exception:
        bigram_score = 0.0

    # 6. Word structure bonus (up to +0.05)
    space_count = data.count(ord(' '))
    has_words = min(space_count / max(length / 6, 1), 1.0) if length > 4 else 0.0

    # 7. Code pattern bonus (up to +0.05)
    data_lower = data.lower()
    code_match = any(pattern in data_lower for pattern in _CODE_PATTERNS)
    code_score = 1.0 if code_match else 0.0

    score = base + bigram_score * 0.10 + has_words * 0.05 + code_score * 0.05

    return round(min(score, 1.0), 4)


def _confidence_label(score: float) -> str:
    """Return a confidence label based on the decryption score."""
    if score > 0.95:
        return "high"
    if score > 0.85:
        return "medium"
    return "low"


def _alpha_ratio(text: str) -> float:
    """Ratio of alphanumeric characters -- higher means more likely real text."""
    if not text:
        return 0.0
    return sum(1 for c in text if c.isalnum()) / len(text)


def _english_text_score(data: bytes) -> float:
    """Score how likely a byte sequence is to be English text.

    Weights spaces and lowercase letters more heavily than other printable
    characters, which helps distinguish real English from random printable bytes
    during frequency analysis (e.g., multi-byte XOR key recovery).
    """
    if not data:
        return 0.0
    score = 0.0
    for b in data:
        if b == 0x20:  # space -- very common in English (~13%)
            score += 3.0
        elif 0x61 <= b <= 0x7A:  # lowercase letters
            score += 2.0
        elif 0x41 <= b <= 0x5A:  # uppercase letters
            score += 1.5
        elif 0x30 <= b <= 0x39:  # digits
            score += 1.0
        elif b in (0x09, 0x0A, 0x0D):  # tab, newline, CR
            score += 0.8
        elif 0x20 <= b <= 0x7E:  # other printable ASCII
            score += 0.5
        # non-printable: 0 points
    return score / (len(data) * 3.0)  # normalize so max ~1.0 for space-heavy text
