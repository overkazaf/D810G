"""Z3-based equivalence verification for MBA rules."""

from __future__ import annotations
import re as _re
from z3 import Solver, Not, unsat

from d810g_engine.parser import eval_z3


def verify_equivalence(pattern: str, replacement: str, bit_width: int = 32) -> bool:
    """Verify that pattern and replacement are equivalent for all inputs using Z3.

    Returns False (fail-safe) if an expression contains unsupported constructs
    such as function calls (abs, min, max, sign) so that broken rules are
    never silently accepted.
    """
    try:
        lhs, vars_lhs = eval_z3(pattern, bit_width=bit_width)
        # Parse replacement sharing the same variable objects so both sides
        # refer to the same Z3 symbols.  The shared parser returns fresh
        # variables each call, so we build the rhs from scratch and rely on
        # Z3 matching by variable *name* (BitVec("x", 32) is the same
        # symbol as another BitVec("x", 32) within the same context).
        rhs, _vars_rhs = eval_z3(replacement, bit_width=bit_width)
    except ValueError:
        return False  # fail-safe: reject unparseable expressions

    solver = Solver()
    solver.add(Not(lhs == rhs))
    return solver.check() == unsat
