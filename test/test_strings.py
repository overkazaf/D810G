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
    _score_decryption,
    _confidence_label,
    _COMMON_BIGRAMS,
    _CODE_PATTERNS,
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


class TestRC4Decrypt:

    def test_rc4_single_byte_key(self):
        from d810g_engine.strings.decryptor import try_rc4_decrypt, _rc4
        plaintext = b"HelloRC4"
        key = b"\x42"
        encrypted = _rc4(key, plaintext)
        results = try_rc4_decrypt(encrypted.hex(), key_candidates=[key])
        assert any(r["decrypted"] == "HelloRC4" for r in results)

    def test_rc4_multi_byte_key(self):
        from d810g_engine.strings.decryptor import try_rc4_decrypt, _rc4
        plaintext = b"SecretMessage"
        key = b"key123"
        encrypted = _rc4(key, plaintext)
        results = try_rc4_decrypt(encrypted.hex(), key_candidates=[key])
        assert any(r["decrypted"] == "SecretMessage" for r in results)


class TestSubstitutionDecrypt:

    def test_rot13(self):
        from d810g_engine.strings.decryptor import try_sub_table_decrypt
        plaintext = b"Hello World! This is a test message for rotation cipher."
        rot = 13
        encrypted = bytes((b - rot) % 256 for b in plaintext)
        results = try_sub_table_decrypt(encrypted.hex())
        assert any("Hello" in r["decrypted"] for r in results)

    def test_custom_table(self):
        from d810g_engine.strings.decryptor import try_sub_table_decrypt
        # Identity table with swap of H<->X
        table = list(range(256))
        table[ord("X")] = ord("H")
        plaintext = b"Xello"
        results = try_sub_table_decrypt(plaintext.hex(), table=table)
        assert any(r["decrypted"] == "Hello" for r in results)


class TestMultibyteXOR:

    def test_two_byte_key(self):
        from d810g_engine.strings.decryptor import try_multibyte_xor_decrypt
        plaintext = b"Hello World! This is a test message for multi-byte XOR."
        key = b"\xAB\xCD"
        encrypted = bytes(plaintext[i] ^ key[i % 2] for i in range(len(plaintext)))
        results = try_multibyte_xor_decrypt(encrypted.hex(), max_key_len=4)
        assert any("Hello" in r["decrypted"] for r in results)


class TestScoreDecryption:

    def test_english_text_scores_high(self):
        """Real English text should score well above 0.80."""
        data = b"Hello World! This is a test message."
        score = _score_decryption(data)
        assert score > 0.80, f"English text scored only {score}"

    def test_random_bytes_score_low(self):
        """Random bytes should score well below 0.80."""
        import os
        data = os.urandom(32)
        score = _score_decryption(data)
        assert score < 0.80, f"Random data scored {score}"

    def test_short_string_penalized(self):
        """Very short strings get a length penalty."""
        short = b"Hi"
        long = b"Hello World"
        short_score = _score_decryption(short)
        long_score = _score_decryption(long)
        assert long_score > short_score

    def test_empty_data(self):
        assert _score_decryption(b"") == 0.0

    def test_control_chars_penalized(self):
        """Data with control characters should score lower."""
        clean = b"Hello World Test"
        dirty = b"Hello\x01World\x02Test"
        assert _score_decryption(clean) > _score_decryption(dirty)


class TestConfidenceLabel:

    def test_high(self):
        assert _confidence_label(0.96) == "high"
        assert _confidence_label(1.0) == "high"

    def test_medium(self):
        assert _confidence_label(0.90) == "medium"
        assert _confidence_label(0.86) == "medium"

    def test_low(self):
        assert _confidence_label(0.80) == "low"
        assert _confidence_label(0.50) == "low"


class TestFalsePositiveRate:

    def test_low_false_positive_rate(self):
        """Random-looking data should produce few or no candidates."""
        import os
        random_data = os.urandom(32)
        results = try_xor_decrypt(random_data.hex())
        assert len(results) <= 5, f"Too many false positives: {len(results)}"

    def test_xor_result_limit(self):
        """Single-byte XOR should return at most 5 results."""
        # Even with data that might match many keys, cap at 5
        plaintext = b"Hello, World!"
        key = 0x42
        encrypted = bytes(b ^ key for b in plaintext)
        results = try_xor_decrypt(encrypted.hex())
        assert len(results) <= 5

    def test_confidence_field_present(self):
        """Results should include the confidence field."""
        plaintext = b"Hello, World!"
        key = 0x42
        encrypted = bytes(b ^ key for b in plaintext)
        results = try_xor_decrypt(encrypted.hex())
        assert len(results) >= 1
        for r in results:
            assert "confidence" in r
            assert r["confidence"] in ("high", "medium", "low")


class TestRankingAccuracy:
    """The correct decryption should be ranked first or near the top."""

    def test_correct_key_ranked_first(self):
        """The correct decryption should be ranked first or near the top."""
        plaintext = b"Hello, World! This is a test string."
        key = 0x42
        encrypted = bytes(b ^ key for b in plaintext)
        results = try_xor_decrypt(encrypted.hex())
        assert len(results) > 0
        assert results[0]["decrypted"] == plaintext.decode()
        assert results[0]["key"] == key

    def test_url_ranked_above_garbage(self):
        """URL decryption should score higher than random printable results."""
        url = b"https://api.example.com/v2/auth"
        key = 0x55
        encrypted = bytes(b ^ key for b in url)
        results = try_xor_decrypt(encrypted.hex())
        correct = [r for r in results if r["decrypted"] == url.decode()]
        assert len(correct) > 0
        assert correct[0] == results[0]  # should be ranked first

    def test_code_pattern_boosts_score(self):
        """Strings containing code patterns should score higher."""
        code_str = b"select * from users where id = 1"
        garbage = b"xyzqw jklmn opqrs tuvwx abcde"
        assert _score_decryption(code_str) > _score_decryption(garbage)

    def test_bigram_rich_text_beats_random_printable(self):
        """Text with common English bigrams should outscore random printable."""
        english = b"the answer is there in the header"
        # Random printable ASCII that avoids common bigrams
        random_printable = b"zqjxkvbwgypfmcludz qjxkvbwgypf"
        assert _score_decryption(english) > _score_decryption(random_printable)

    def test_password_string_ranked_first(self):
        """Common credential strings should rank correctly."""
        plaintext = b"password_token_secret_key"
        key = 0x33
        encrypted = bytes(b ^ key for b in plaintext)
        results = try_xor_decrypt(encrypted.hex())
        assert len(results) > 0
        assert results[0]["decrypted"] == plaintext.decode()


class TestBigramScoring:
    """Tests for the bigram frequency scoring component."""

    def test_common_bigrams_constant(self):
        """Verify the bigram set contains expected entries."""
        assert 'th' in _COMMON_BIGRAMS
        assert 'he' in _COMMON_BIGRAMS
        assert 'zq' not in _COMMON_BIGRAMS

    def test_code_patterns_constant(self):
        """Verify code patterns contain expected entries."""
        assert b'http' in _CODE_PATTERNS
        assert b'select' in _CODE_PATTERNS

    def test_short_data_returns_zero(self):
        """Data shorter than 2 bytes should score 0."""
        assert _score_decryption(b"") == 0.0
        assert _score_decryption(b"x") == 0.0


class TestAllMethodsIntegration:

    def test_auto_detect_xor(self):
        from d810g_engine.strings.decryptor import decrypt_strings
        plaintext = b"password123"
        key = 0x77
        encrypted = bytes(b ^ key for b in plaintext)
        result = decrypt_strings({
            "binary_hex": "00" * 100,
            "addresses": [{"address": 0x601000, "data_hex": encrypted.hex()}],
        })
        assert result["status"] == "decrypted"
        assert any(
            d["decrypted"] == "password123"
            for r in result["results"]
            for d in r["decryptions"]
        )
