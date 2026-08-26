"""Vector stub: slow-SSE / slow read (CWE-400: Uncontrolled Resource
Consumption -- Slowloris-style).

NOT IMPLEMENTED HERE -- see oversized_body.py's docstring for the general
policy (load generation is the vector-implementation agent's job; this
harness only ships measurement/integration plumbing).

Mitigation counterpart (Phase 4): idle/slow-read timeout.
"""
from __future__ import annotations

from ..interface import AttackContext, AttackModule, AttackOutcome, Transport
from ..registry import register_module


@register_module("slow_sse_slow_read")
class SlowSseSlowReadModule(AttackModule):
    cwe = "CWE-400"
    description = (
        "Open an SSE stream (or HTTP response) and read it at a trickle, "
        "or send request bytes at a trickle, to tie up target connection "
        "slots/threads for as long as possible (Slowloris-style)."
    )
    supported_transports = (Transport.SSE, Transport.STREAMABLE_HTTP)

    def run(self, ctx: AttackContext) -> AttackOutcome:
        self.validate_context(ctx)
        raise NotImplementedError(
            "slow_sse_slow_read load generation is the vector-implementation "
            "agent's responsibility; this scaffold only wires up "
            "config/registry/results plumbing. See harness/REPORT.md."
        )
