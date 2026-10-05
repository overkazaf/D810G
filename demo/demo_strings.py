#!/usr/bin/env python3
"""D810G String Decryption Demo — XOR, RC4, multi-byte XOR, substitution."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from d810g_engine.strings.decryptor import (
    try_xor_decrypt,
    try_rc4_decrypt,
    try_multibyte_xor_decrypt,
    try_sub_table_decrypt,
    _rc4,
    decrypt_strings,
)


def banner(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def demo_method(name, plaintext, encrypt_fn, decrypt_fn, **kwargs):
    encrypted = encrypt_fn(plaintext)
    print(f"  Method: {name}")
    print(f"  Original:  {plaintext.decode()}")
    hex_str = encrypted.hex()
    print(f"  Encrypted: {hex_str[:40]}{'...' if len(hex_str) > 40 else ''}")
    results = decrypt_fn(encrypted.hex(), **kwargs)
    if results:
        best = results[0]
        print(f"  Decrypted: {best['decrypted']}")
        key_display = best.get("key", best.get("key_hex", best.get("rotation", "?")))
        print(f"  Key:       {key_display}")
        print(f"  Score:     {best['score']}")
        if best["decrypted"] == plaintext.decode():
            print(f"  [MATCH]")
        else:
            print(f"  [PARTIAL]")
    else:
        print(f"  [NO VALID DECRYPTION FOUND]")
    print()


def main():
    banner("D810G Demo: String Decryption")

    print("OLLVM and other obfuscators encrypt string literals in the binary.")
    print("D810G tries multiple decryption methods and ranks results by")
    print("printable character score.\n")

    print("-" * 70)
    print("1. Single-byte XOR (most common in OLLVM)")
    print("-" * 70)
    demo_method(
        "XOR (key=0x42)",
        b"Hello, World!",
        lambda p: bytes(b ^ 0x42 for b in p),
        try_xor_decrypt,
    )

    print("-" * 70)
    print("2. Multi-byte XOR (repeating key)")
    print("-" * 70)
    key = b"\xAB\xCD"
    demo_method(
        f"Multi-byte XOR (key={key.hex()})",
        b"This is a secret message that needs to be long enough for analysis!",
        lambda p: bytes(p[i] ^ key[i % len(key)] for i in range(len(p))),
        try_multibyte_xor_decrypt,
        max_key_len=4,
    )

    print("-" * 70)
    print("3. RC4 stream cipher")
    print("-" * 70)
    rc4_key = b"\x55"
    demo_method(
        f"RC4 (key={rc4_key.hex()})",
        b"Encrypted with RC4",
        lambda p: _rc4(rc4_key, p),
        try_rc4_decrypt,
        key_candidates=[rc4_key],
    )

    print("-" * 70)
    print("4. ROT-N substitution")
    print("-" * 70)
    rot = 13
    demo_method(
        f"ROT-{rot}",
        b"This string was rotated by thirteen positions in the byte table!!!",
        lambda p: bytes((b - rot) % 256 for b in p),
        try_sub_table_decrypt,
    )

    banner("Auto-Detection: Unknown Encryption")

    print("When the encryption method is unknown, D810G tries ALL methods")
    print("and ranks results by likelihood.\n")

    secrets = [
        ("API key", b"sk_live_abc123def456"),
        ("URL", b"https://api.example.com/v2/users"),
        ("SQL query", b"SELECT * FROM users WHERE role='admin'"),
    ]

    for label, plaintext in secrets:
        key_byte = 0x77
        encrypted = bytes(b ^ key_byte for b in plaintext)
        result = decrypt_strings({
            "binary_hex": "00" * 100,
            "addresses": [{"address": 0x601000, "data_hex": encrypted.hex()}],
        })
        print(f"  [{label}]")
        print(f"    Encrypted: {encrypted.hex()[:50]}...")
        if result["results"]:
            best = result["results"][0]["decryptions"][0]
            print(f"    Decrypted: {best['decrypted']}")
            key_display = best.get("key", best.get("key_hex", "?"))
            print(f"    Method:    {best['method']}, key={key_display}")
        else:
            print(f"    No decryption found")
        print()


if __name__ == "__main__":
    main()
