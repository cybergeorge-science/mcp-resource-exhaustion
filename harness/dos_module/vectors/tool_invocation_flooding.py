"""Vector stub: tool-invocation flooding (CWE-400: Uncontrolled Resource
Consumption).

NOT IMPLEMENTED HERE -- see oversized_body.py's docstring for the general
policy (load generation is the vector-implementation agent's job; this
harness only ships measurement/integration plumbing).

Mitigation counterpart (Phase 4): tool-invocation rate limit.
"""
from __future__ import annotations

from ..interface import AttackContext, AttackModule, AttackOutcome, Transport
from ..registry import register_module


@register_module("tool_invocation_flooding")
class ToolInvocationFloodingModule(AttackModule):
    cwe = "CWE-400"
    description = (
        "Call one or more registered tools far faster than the target "
        "server is provisioned for, exhausting worker threads/CPU/queue "
        "capacity."
    )
    supported_transports = (Transport.STDIO, Transport.STREAMABLE_HTTP, Transport.SSE)

    def run(self, ctx: AttackContext) -> AttackOutcome:
        self.validate_context(ctx)
        raise NotImplementedError(
            "tool_invocation_flooding load generation is the "
            "vector-implementation agent's responsibility; this scaffold "
            "only wires up config/registry/results plumbing. See "
            "harness/REPORT.md."
        )
