"""Vector stub: deeply nested JSON (CWE-770: Allocation of Resources
Without Limits or Throttling).

NOT IMPLEMENTED HERE -- see oversized_body.py's docstring for the general
policy (load generation is the vector-implementation agent's job; this
harness only ships measurement/integration plumbing).

Mitigation counterpart (Phase 4): JSON depth limit.
"""
from __future__ import annotations

from ..interface import AttackContext, AttackModule, AttackOutcome, Transport
from ..registry import register_module


@register_module("deeply_nested_json")
class DeeplyNestedJsonModule(AttackModule):
    cwe = "CWE-770"
    description = (
        "Send a JSON-RPC payload with extreme nesting depth to trigger "
        "expensive/recursive parsing or stack exhaustion in the target's "
        "JSON decoder."
    )
    supported_transports = (Transport.STREAMABLE_HTTP, Transport.SSE, Transport.STDIO)

    def run(self, ctx: AttackContext) -> AttackOutcome:
        self.validate_context(ctx)
        raise NotImplementedError(
            "deeply_nested_json load generation is the vector-implementation "
            "agent's responsibility; this scaffold only wires up "
            "config/registry/results plumbing. See harness/REPORT.md."
        )
