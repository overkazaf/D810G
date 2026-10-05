---
layout: default
title: String Decryption
---

**English** | [中文](../cn/modules/strings)

# String Decryption

D810G detects and decrypts OLLVM-encrypted strings using multiple decryption methods.

## Supported Methods

| Method | Description |
|--------|-------------|
| Single-byte XOR | Try all 256 keys |
| Multi-byte XOR | Frequency analysis to recover key |
| XOR with index | `byte[i] ^= key ^ i` |
| RC4 | Stream cipher brute-force |
| ROT-N | All 255 rotations |
| Substitution table | Custom 256-byte lookup |

## How It Works

1. **Scan** sections (`.data`, `.rodata`) for high-entropy regions
2. **Try** all decryption methods on each candidate
3. **Score** results by printable character ratio
4. **Rank** and return top candidates

[← Back to Home](../)
