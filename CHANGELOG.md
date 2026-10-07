# Changelog

## [0.2.0] - 2026-10-07

### Added
- Multi-pass MBA simplification with sub-expression support (`--deep` CLI flag)
- 7-pass deobfuscation pipeline (deflat_ollvm -> deflat_tigress -> bcf -> opaque -> mba -> dce -> strings)
- Tigress VM devirtualization with bytecode tracing and pseudocode generation
- Capstone-based VM handler classification (15+ semantic types)
- Advanced opaque predicates with integer arithmetic and number theory detection
- Bogus Control Flow detection and removal
- Dead Code Elimination with BFS reachability analysis
- String decryption: XOR, multi-byte XOR, RC4, ROT-N, substitution table
- Interactive rule editor (REPL mode)
- Standalone CLI with simplify, opaque, rules, batch, interactive, pipeline commands
- Ghidra Analyzer integration for automatic deobfuscation
- ARM32 architecture support (Unicorn + Keystone + Capstone)
- Shared expression parser module (consolidated 4 duplicates)
- Multi-factor string decryption scoring with bigram and code pattern analysis
- GitHub Pages documentation site (English + Chinese)
- Java/Gradle CI with Ghidra build verification
- SVG terminal recordings in documentation
- 12 realistic binary test cases

### Changed
- MBA rules expanded from 10 to 96 (6 rule files, 0 duplicates, all Z3-verified)
- Pipeline now propagates block graph state between passes
- Patch deduplication across pipeline iterations
- PcodeUtils extracts 9 block properties (was 2)
- DeobfuscationOrchestrator calls pipeline.run instead of just deflat.run
- String decryption false positives reduced from 190+ to ~4 candidates

### Fixed
- 5 broken MBA rules using unsupported operators (abs, min, max, sign, div)
- Z3 verifier silently dropping unknown operators (>>, /, %)
- Opaque predicate parser crashes on empty/non-boolean input
- VM handler RET-priority misclassification
- Advanced opaque integer-mode false positive on multiplication overflow
- Pipeline duplicate patches across iterations
- Deep simplification returning verified=False for unchanged expressions

## [0.1.0] - 2026-10-05

### Added
- Initial release
- OLLVM control flow deflattening with Unicorn emulation
- Tigress CFF support (indirect jump table + if-chain)
- MBA expression simplification with 10 rules and Z3 verification
- Opaque predicate elimination
- Java Ghidra plugin with right-click menu
- Python engine with JSON-RPC IPC
- 32 initial tests
