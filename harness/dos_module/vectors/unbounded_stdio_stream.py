"""Vector stub: unbounded stdio stream (CWE-770: Allocation of Resources
Without Limits or Throttling).

NOT IMPLEMENTED HERE -- see oversized_body.py's docstring for the general
policy (load generation is the vector-implementation agent's job; this
harness only ships measurement/integration plumbing).

Mitigation counterpart (Phase 4): read-buffer framing limit.
"""
from __future__ import annotations

from ..interface import AttackContext, AttackModule, AttackOutcome, Transport
from ..registry import register_module


@register_module("unbounded_stdio_stream")
class UnboundedStdioStreamModule(AttackModule):
    cwe = "CWE-770"
    description = (
        "Write an unbounded / very long single JSON-RPC line (or a stream "
        "that never terminates a frame) to the target's stdio transport to "
        "grow its read buffer without limit."
    )
    supported_transports = (Transport.STDIO,)

    def run(self, ctx: AttackContext) -> AttackOutcome:
        self.validate_context(ctx)
        raise NotImplementedError(
            "unbounded_stdio_stream load generation is the "
            "vector-implementation agent's responsibility; this scaffold "
            "only wires up config/registry/results plumbing. See "
            "harness/REPORT.md."
        )
