"""D810G Interactive Rule Editor — test, create, and verify MBA rules.

Usage:
    python -m d810g_engine cli interactive

Commands:
    test <expression>           Test simplification against all loaded rules
    verify <pattern> = <repl>   Verify equivalence with Z3
    add <id> <pattern> = <repl> Add a new rule to the working set
    remove <id>                 Remove a rule from the working set
    list                        List all loaded rules
    load <file.json>            Load rules from file
    save <file.json>            Save working rules to file
    stats                       Show simplification statistics
    help                        Show this help
    quit                        Exit
"""

from __future__ import annotations

import json
import readline  # noqa: F401 — enables arrow keys and history in input()
from pathlib import Path

from d810g_engine.mba import _ast_to_str
from d810g_engine.mba.rules import Rule, load_rules
from d810g_engine.mba.matcher import parse_expr, match_rule
from d810g_engine.mba.verifier import verify_equivalence


RULES_DIR = Path(__file__).parent.parent.parent / "data" / "rules"


class InteractiveEditor:
    def __init__(self):
        self.rules: list[Rule] = []
        self.custom_rules: list[Rule] = []
        self.stats = {"tested": 0, "simplified": 0, "verified": 0, "failed": 0}
        self._load_all_rules()

    def _load_all_rules(self):
        """Load all rule files from data/rules/."""
        self.rules = []
        for rules_file in sorted(RULES_DIR.glob("*.json")):
            try:
                self.rules.extend(load_rules(rules_file))
            except Exception as e:
                print(f"  Warning: failed to load {rules_file.name}: {e}")
        print(f"  Loaded {len(self.rules)} rules from {len(list(RULES_DIR.glob('*.json')))} files")

    def cmd_test(self, expr_str: str):
        """Test an expression against all loaded rules."""
        self.stats["tested"] += 1
        all_rules = self.rules + self.custom_rules

        expr_ast = parse_expr(expr_str)
        matches = []

        for rule in all_rules:
            result = match_rule(expr_ast, rule)
            if result is not None:
                simplified = _ast_to_str(result)
                verified = verify_equivalence(expr_str, simplified)
                matches.append((rule, simplified, verified))

        if not matches:
            print(f"  No rules matched: {expr_str}")
            return

        self.stats["simplified"] += 1
        for rule, simplified, verified in matches:
            status = "Z3 verified" if verified else "NOT VERIFIED"
            if verified:
                self.stats["verified"] += 1
            else:
                self.stats["failed"] += 1
            print(f"  {expr_str}")
            print(f"  -> {simplified}  [{status}]")
            print(f"     Rule: {rule.id} — {rule.description}")

    def cmd_verify(self, args: str):
        """Verify equivalence: verify <pattern> = <replacement>"""
        if "=" not in args:
            print("  Usage: verify <pattern> = <replacement>")
            return

        parts = args.split("=", 1)
        pattern = parts[0].strip()
        replacement = parts[1].strip()

        for bits in [8, 16, 32, 64]:
            result = verify_equivalence(pattern, replacement, bit_width=bits)
            status = "EQUIVALENT" if result else "NOT EQUIVALENT"
            print(f"  {bits}-bit: {status}")

    def cmd_add(self, args: str):
        """Add a new rule: add <id> <pattern> = <replacement>"""
        parts = args.split(None, 1)
        if len(parts) < 2 or "=" not in parts[1]:
            print("  Usage: add <rule_id> <pattern> = <replacement>")
            return

        rule_id = parts[0]
        expr_parts = parts[1].split("=", 1)
        pattern = expr_parts[0].strip()
        replacement = expr_parts[1].strip()

        # Verify first
        verified = verify_equivalence(pattern, replacement)
        if not verified:
            print(f"  WARNING: Z3 says these are NOT equivalent!")
            confirm = input("  Add anyway? (y/N): ").strip().lower()
            if confirm != "y":
                print("  Cancelled.")
                return

        rule = Rule(
            id=rule_id,
            pattern=pattern,
            replacement=replacement,
            commutative=False,
            description="Custom rule added interactively",
        )
        self.custom_rules.append(rule)
        status = "verified" if verified else "UNVERIFIED"
        print(f"  Added rule '{rule_id}': {pattern} -> {replacement} [{status}]")

    def cmd_remove(self, rule_id: str):
        """Remove a custom rule by ID."""
        rule_id = rule_id.strip()
        before = len(self.custom_rules)
        self.custom_rules = [r for r in self.custom_rules if r.id != rule_id]
        if len(self.custom_rules) < before:
            print(f"  Removed rule '{rule_id}'")
        else:
            print(f"  Rule '{rule_id}' not found in custom rules")

    def cmd_list(self):
        """List all loaded rules."""
        print(f"\n  Built-in rules ({len(self.rules)}):")
        for r in self.rules:
            print(f"    {r.id}: {r.pattern} -> {r.replacement}")

        if self.custom_rules:
            print(f"\n  Custom rules ({len(self.custom_rules)}):")
            for r in self.custom_rules:
                print(f"    {r.id}: {r.pattern} -> {r.replacement}")

        print(f"\n  Total: {len(self.rules) + len(self.custom_rules)} rules")

    def cmd_save(self, filename: str):
        """Save custom rules to a JSON file."""
        filename = filename.strip()
        if not filename.endswith(".json"):
            filename += ".json"

        path = RULES_DIR / filename
        data = {
            "name": Path(filename).stem,
            "description": "Custom rules created via interactive editor",
            "rules": [
                {
                    "id": r.id,
                    "pattern": r.pattern,
                    "replacement": r.replacement,
                    "commutative": r.commutative,
                    "description": r.description,
                }
                for r in self.custom_rules
            ],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  Saved {len(self.custom_rules)} rules to {path}")

    def cmd_load(self, filename: str):
        """Load additional rules from a file."""
        filename = filename.strip()
        path = RULES_DIR / filename if not Path(filename).is_absolute() else Path(filename)
        try:
            new_rules = load_rules(path)
            self.rules.extend(new_rules)
            print(f"  Loaded {len(new_rules)} rules from {path.name}")
        except Exception as e:
            print(f"  Error: {e}")

    def cmd_stats(self):
        """Show simplification statistics."""
        print(f"\n  Session Statistics:")
        print(f"    Expressions tested:  {self.stats['tested']}")
        print(f"    Successfully simplified: {self.stats['simplified']}")
        print(f"    Z3 verified:         {self.stats['verified']}")
        print(f"    Verification failed: {self.stats['failed']}")
        print(f"    Built-in rules:      {len(self.rules)}")
        print(f"    Custom rules:        {len(self.custom_rules)}")

    def cmd_help(self):
        """Show help."""
        print("""
  D810G Interactive Rule Editor

  Commands:
    test <expr>              Test simplification against all rules
    verify <p> = <r>         Verify equivalence with Z3 (8/16/32/64-bit)
    add <id> <p> = <r>       Add a new custom rule
    remove <id>              Remove a custom rule
    list                     List all loaded rules
    load <file>              Load rules from file
    save <file>              Save custom rules to file
    stats                    Show session statistics
    help                     Show this help
    quit / exit              Exit

  Examples:
    test (x | y) - (x & y)
    verify (x & y) + (x ^ y) = x | y
    add my_rule_1 ~(~x & ~y) = x | y
    save my_custom_rules.json
""")

    def run(self):
        """Main REPL loop."""
        print("\n  D810G Interactive Rule Editor")
        print("  Type 'help' for commands, 'quit' to exit.\n")

        while True:
            try:
                line = input("d810g> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            parts = line.split(None, 1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if cmd in ("quit", "exit", "q"):
                break
            elif cmd == "test":
                if not args:
                    print("  Usage: test <expression>")
                else:
                    self.cmd_test(args)
            elif cmd == "verify":
                self.cmd_verify(args)
            elif cmd == "add":
                self.cmd_add(args)
            elif cmd == "remove":
                self.cmd_remove(args)
            elif cmd == "list":
                self.cmd_list()
            elif cmd == "save":
                if not args:
                    print("  Usage: save <filename.json>")
                else:
                    self.cmd_save(args)
            elif cmd == "load":
                if not args:
                    print("  Usage: load <filename.json>")
                else:
                    self.cmd_load(args)
            elif cmd == "stats":
                self.cmd_stats()
            elif cmd == "help":
                self.cmd_help()
            else:
                # Try as an expression to test
                self.cmd_test(line)

        print("  Goodbye!")


def main():
    editor = InteractiveEditor()
    editor.run()
