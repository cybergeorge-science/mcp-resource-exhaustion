"""Vector stub: initialize / session flood (CWE-400: Uncontrolled Resource
Consumption).

NOT IMPLEMENTED HERE -- see oversized_body.py's docstring for the general
policy (load generation is the vector-implementation agent's job; this
harness only ships measurement/integration plumbing).

Mitigation counterpart (Phase 4): session creation rate limit.
"""
from __future__ import annotations

from ..interface import AttackContext, AttackModule, AttackOutcome, Transport
from ..registry import register_module


@register_module("init_session_flood")
class InitSessionFloodModule(AttackModule):
    cwe = "CWE-400"
    description = (
        "Repeatedly open new MCP sessions/initialize handshakes faster than "
        "the target can reap them, exhausting session-table memory or "
        "handshake CPU time."
    )
    supported_transports = (Transport.STREAMABLE_HTTP, Transport.SSE, Transport.STDIO)

    def run(self, ctx: AttackContext) -> AttackOutcome:
        self.validate_context(ctx)
        raise NotImplementedError(
            "init_session_flood load generation is the vector-implementation "
            "agent's responsibility; this scaffold only wires up "
            "config/registry/results plumbing. See harness/REPORT.md."
        )
