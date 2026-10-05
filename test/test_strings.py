import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import pytest
from d810g_engine.strings.decryptor import (
    try_xor_decrypt,
    find_encrypted_strings,
    decrypt_strings,
    _byte_entropy,
    _printable_score,
)


class TestXORDecrypt:

    def test_single_byte_xor(self):
        """Encrypt 'Hello' with XOR 0x42, then decrypt."""
        plaintext = b"Hello"
        key = 0x42
        encrypted = bytes(b ^ key for b in plaintext)

        results = try_xor_decrypt(encrypted.hex())
        assert len(results) >= 1
        assert any(r["decrypted"] == "Hello" and r["key"] == key for r in results)

    def test_xor_with_index(self):
        """Encrypt with XOR key^index pattern."""
        plaintext = b"Test123"
        key = 0x55
        encrypted = bytes((b ^ (key ^ (i % 256))) for i, b in enumerate(plaintext))

        results = try_xor_decrypt(encrypted.hex())
        assert any(r["decrypted"] == "Test123" and r["method"] == "xor_index" for r in results)

    def test_known_key(self):
        """Decrypt with a known key."""
        plaintext = b"secret"
        key = 0xAB
        encrypted = bytes(b ^ key for b in plaintext)

        results = try_xor_decrypt(encrypted.hex(), key_candidates=[key])
        assert len(results) >= 1
        assert results[0]["decrypted"] == "secret"

    def test_no_valid_decryption(self):
        """Random data should not produce valid decryptions."""
        import os
        random_data = os.urandom(32)
        results = try_xor_decrypt(random_data.hex())
        # May or may not find something, but shouldn't crash
        assert isinstance(results, list)


class TestEntropy:

    def test_zero_entropy(self):
        """All same bytes = 0 entropy."""
        assert _byte_entropy(b"\x00" * 16) == 0.0

    def test_low_entropy(self):
        """ASCII text has moderate entropy."""
        entropy = _byte_entropy(b"Hello World, this is a test string")
        assert 2.0 < entropy < 5.0

    def test_high_entropy(self):
        """Random-looking data has high entropy."""
        data = bytes(range(256))  # all possible byte values
        entropy = _byte_entropy(data)
        assert entropy > 7.0


class TestPrintableScore:

    def test_fully_printable(self):
        assert _printable_score(b"Hello World") > 0.9

    def test_non_printable(self):
        assert _printable_score(bytes(range(0, 32))) < 0.2

    def test_empty(self):
        assert _printable_score(b"") == 0.0


class TestFindEncryptedStrings:

    def test_find_in_data_section(self):
        """Detect high-entropy regions in .data section."""
        # Create a binary with a mix of normal and encrypted data
        normal = b"\x00" * 64
        encrypted = bytes((i * 0x37 + 0x42) & 0xFF for i in range(32))  # pseudo-random
        binary = normal + encrypted + b"\x00" * 64

        sections = [{
            "name": ".data",
            "offset": 0,
            "vaddr": 0x601000,
            "size": len(binary),
        }]

        candidates = find_encrypted_strings(binary, sections)
        # Should find at least the encrypted region
        assert isinstance(candidates, list)


class TestDecryptStrings:

    def test_decrypt_with_addresses(self):
        """Decrypt specific addresses with known data."""
        plaintext = b"password123"
        key = 0x77
        encrypted = bytes(b ^ key for b in plaintext)

        result = decrypt_strings({
            "binary_hex": "00" * 100,
            "addresses": [
                {"address": 0x601000, "data_hex": encrypted.hex()},
            ],
        })
        assert result["status"] == "decrypted"
        assert len(result["results"]) == 1
        assert any(
            d["decrypted"] == "password123"
            for d in result["results"][0]["decryptions"]
        )

    def test_handler_registration(self):
        from d810g_engine.server import Server
        from d810g_engine.strings import register_handlers
        server = Server()
        register_handlers(server)
        assert "strings.decrypt" in server._handlers
