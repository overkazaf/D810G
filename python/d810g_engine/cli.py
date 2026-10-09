#!/usr/bin/env python3
"""D810G CLI — use the deobfuscation engine standalone, without Ghidra.

Usage:
    python -m d810g_engine cli simplify "(x | y) - (x & y)"
    python -m d810g_engine cli simplify --rules mba_ollvm.json "(x ^ y) + 2 * (x & y)"
    python -m d810g_engine cli opaque "x == x"
    python -m d810g_engine cli opaque "(x & 1) == 2" --bits 64
    python -m d810g_engine cli rules                    # list all available rules
    python -m d810g_engine cli rules --verify           # verify all rules with Z3
    python -m d810g_engine cli batch < expressions.txt  # one expression per line
    python -m d810g_engine cli verify "(a ^ b) + 2 * (a & b)" "a + b"  # check LLM output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from d810g_engine.mba import simplify_expression
from d810g_engine.mba.rules import load_rules
from d810g_engine.mba.verifier import verify_equivalence
from d810g_engine.opaque.predicate import classify_predicate

RULES_DIR = Path(__file__).parent.parent.parent / "data" / "rules"


def cmd_simplify(args: argparse.Namespace) -> None:
    """Simplify an MBA expression."""
    if args.deep:
        from d810g_engine.mba import simplify_expression_deep
        result = simplify_expression_deep({
            "expression": args.expression,
            "max_iterations": 10,
            "verify": not args.no_verify,
        })
        if args.json:
            print(json.dumps(result, indent=2))
            return
        print(f"  {args.expression}")
        for step in result.get("chain", []):
            print(f"  -> {step['after']}  (step {step['step']}, {step['rule_id']})")
        if result.get("verified"):
            print(f"  Final: Z3 verified equivalent")
        print(f"  Iterations: {result['iterations']}, fixpoint: {result['fixpoint']}")
        return

    result = simplify_expression({
        "expression": args.expression,
        "rules": args.rules,
        "verify": not args.no_verify,
    })

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if result["rule_id"]:
        verified = " (Z3 verified)" if result.get("verified") else ""
        print(f"  {args.expression}")
        print(f"  -> {result['simplified']}{verified}")
        print(f"  Rule: {result['rule_id']}")
    else:
        print(f"  {args.expression}")
        print(f"  -> (no simplification found)")


def cmd_opaque(args: argparse.Namespace) -> None:
    """Classify an opaque predicate."""
    result = classify_predicate(
        args.expression,
        bit_width=args.bits,
        signed=not args.unsigned,
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if result["classification"] == "error":
        print(f"  {args.expression}")
        print(f"  -> ERROR: {result.get('error', 'unknown')}")
        return

    icons = {
        "always_true": "ALWAYS TRUE  -- opaque, can be eliminated",
        "always_false": "ALWAYS FALSE -- opaque, can be eliminated",
        "dynamic": "DYNAMIC      -- real condition, keep as-is",
    }
    print(f"  {args.expression}")
    print(f"  -> {icons[result['classification']]}")


def cmd_rules(args: argparse.Namespace) -> None:
    """List or verify available MBA rules."""
    total = 0
    for rules_file in sorted(RULES_DIR.glob("*.json")):
        rules = load_rules(rules_file)
        print(f"\n  {rules_file.name} ({len(rules)} rules):")

        for rule in rules:
            if args.verify:
                try:
                    ok = verify_equivalence(rule.pattern, rule.replacement, bit_width=32)
                    status = "OK" if ok else "FAILED"
                except Exception as e:
                    status = f"ERROR: {e}"
                print(f"    [{status}] {rule.id}: {rule.pattern} -> {rule.replacement}")
            else:
                print(f"    {rule.id}: {rule.pattern} -> {rule.replacement}")
            total += 1

    print(f"\n  Total: {total} rules")


def cmd_pipeline(args: argparse.Namespace) -> None:
    """Run full deobfuscation pipeline on a block graph."""
    import json
    with open(args.input_file) as f:
        params = json.load(f)
    if args.passes:
        params["passes"] = args.passes
    from d810g_engine.pipeline.orchestrator import run_pipeline
    result = run_pipeline(params)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Pipeline: {result['summary']}")
        for p in result.get("passes", []):
            print(f"    [{p['name']}] {p['status']} — {p['patches']} patches ({p['time_ms']}ms)")


def cmd_verify(args: argparse.Namespace) -> int:
    """Prove an (LLM-proposed) deobfuscation equivalent, audit its constants."""
    from d810g_engine.llm_verify import verify_llm_output

    known = [int(tok, 0) for tok in " ".join(args.constants).replace(",", " ").split()]
    result = verify_llm_output(
        args.original,
        args.candidate,
        bit_widths=args.bits,
        known_constants=known,
        signed=not args.unsigned,
        timeout_ms=args.timeout,
    )
    ok = result["equivalent"] and not result["suspicious_constants"]

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if ok else 1

    print(f"  original:  {args.original}")
    print(f"  candidate: {args.candidate}")
    if "error" in result:
        print(f"  -> ERROR: {result['error']}")
    for bits, res in result["widths"].items():
        if res["result"] == "equivalent":
            print(f"  {bits}-bit: EQUIVALENT (Z3 proof)")
        elif res["result"] == "counterexample":
            cex = res["counterexample"]
            inputs = ", ".join(f"{k}={hex(v)}" for k, v in cex["inputs"].items())
            print(f"  {bits}-bit: COUNTEREXAMPLE  {inputs or '(no inputs)'}")
            print(f"           original -> {_fmt_val(cex['original_value'])}, "
                  f"candidate -> {_fmt_val(cex['candidate_value'])}")
        elif res["result"] == "unknown":
            print(f"  {bits}-bit: UNKNOWN (solver timeout, not verified)")
    for c in result["suspicious_constants"]:
        tag = "HEXSPEAK" if c["hexspeak"] else "UNTRACED"
        print(f"  [{tag}] constant {c['hex']}: {c['reason']}")
    print(f"  Verdict: {'ACCEPT' if ok else 'REJECT'}")
    return 0 if ok else 1


def _fmt_val(val) -> str:
    return str(val) if isinstance(val, bool) else hex(val)


def cmd_batch(args: argparse.Namespace) -> None:
    """Process multiple expressions from stdin."""
    rules_file = args.rules
    count = 0
    simplified = 0

    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        result = simplify_expression({
            "expression": line,
            "rules": rules_file,
            "verify": True,
        })
        count += 1

        if result["rule_id"]:
            simplified += 1
            verified = " [Z3 OK]" if result.get("verified") else ""
            print(f"  {line} -> {result['simplified']}{verified}  ({result['rule_id']})")
        else:
            print(f"  {line} -> (unchanged)")

    print(f"\n  Processed {count} expressions, simplified {simplified}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="d810g",
        description="D810G Deobfuscation Engine CLI",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # simplify
    p_simp = sub.add_parser("simplify", help="Simplify an MBA expression")
    p_simp.add_argument("expression", help="MBA expression to simplify")
    p_simp.add_argument("--rules", default="mba_basic.json", help="Rules file to use")
    p_simp.add_argument("--no-verify", action="store_true", help="Skip Z3 verification")
    p_simp.add_argument("--deep", action="store_true", help="Iterative multi-pass simplification")
    p_simp.add_argument("--json", action="store_true", help="Output as JSON")
    p_simp.set_defaults(func=cmd_simplify)

    # opaque
    p_opaq = sub.add_parser("opaque", help="Classify an opaque predicate")
    p_opaq.add_argument("expression", help="Conditional expression to classify")
    p_opaq.add_argument("--bits", type=int, default=32, help="Bit width (default: 32)")
    p_opaq.add_argument("--unsigned", action="store_true", help="Treat as unsigned")
    p_opaq.add_argument("--json", action="store_true", help="Output as JSON")
    p_opaq.set_defaults(func=cmd_opaque)

    # rules
    p_rules = sub.add_parser("rules", help="List available MBA rules")
    p_rules.add_argument("--verify", action="store_true", help="Verify all rules with Z3")
    p_rules.set_defaults(func=cmd_rules)

    # batch
    p_batch = sub.add_parser("batch", help="Batch simplify expressions from stdin")
    p_batch.add_argument("--rules", default="mba_basic.json", help="Rules file to use")
    p_batch.set_defaults(func=cmd_batch)

    # pipeline
    p_pipe = sub.add_parser("pipeline", help="Run full deobfuscation pipeline on block graph (JSON)")
    p_pipe.add_argument("input_file", help="JSON file with blocks and binary_hex")
    p_pipe.add_argument("--passes", nargs="+", help="Specific passes to run")
    p_pipe.add_argument("--json", action="store_true", help="Output as JSON")
    p_pipe.set_defaults(func=cmd_pipeline)

    # verify
    p_ver = sub.add_parser("verify", help="Formally verify a candidate (e.g. LLM) deobfuscation")
    p_ver.add_argument("original", help="Obfuscated expression")
    p_ver.add_argument("candidate", help="Proposed simplified expression")
    p_ver.add_argument("--bits", type=lambda v: [int(b) for b in v.split(",")],
                       default=[32, 64], help="Comma-separated bit widths (default: 32,64)")
    p_ver.add_argument("--constants", action="append", default=[],
                       help="Constants known from the binary, comma separated (repeatable)")
    p_ver.add_argument("--unsigned", action="store_true", help="Unsigned comparisons / div / mod")
    p_ver.add_argument("--timeout", type=int, default=10000, help="Z3 timeout per query in ms")
    p_ver.add_argument("--json", action="store_true", help="Output as JSON")
    p_ver.set_defaults(func=cmd_verify)

    # interactive
    p_interact = sub.add_parser("interactive", help="Interactive rule editor and tester")
    p_interact.set_defaults(func=lambda args: _run_interactive())

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1

    return args.func(args) or 0


def _run_interactive() -> None:
    """Launch the interactive rule editor."""
    from d810g_engine.interactive import main as interactive_main
    interactive_main()
