"""Vector stub: ReDoS in input validation (CWE-1333: Inefficient Regular
Expression Complexity).

NOT IMPLEMENTED HERE -- see oversized_body.py's docstring for the general
policy (load generation is the vector-implementation agent's job; this
harness only ships measurement/integration plumbing).

Mitigation counterpart (Phase 4): safe regex (e.g. re2-style engine) or a
regex evaluation timeout.
"""
from __future__ import annotations

from ..interface import AttackContext, AttackModule, AttackOutcome, Transport
from ..registry import register_module


@register_module("redos_input_validation")
class RedosInputValidationModule(AttackModule):
    cwe = "CWE-1333"
    description = (
        "Send input crafted to trigger catastrophic backtracking in a "
        "vulnerable validation regex used by the target's request/tool "
        "argument parsing."
    )
    supported_transports = (Transport.STDIO, Transport.STREAMABLE_HTTP, Transport.SSE)

    def run(self, ctx: AttackContext) -> AttackOutcome:
        self.validate_context(ctx)
        raise NotImplementedError(
            "redos_input_validation load generation is the "
            "vector-implementation agent's responsibility; this scaffold "
            "only wires up config/registry/results plumbing. See "
            "harness/REPORT.md."
        )
