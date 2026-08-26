"""Vector stub: oversized message body (CWE-770: Allocation of Resources
Without Limits or Throttling).

NOT IMPLEMENTED HERE. Load generation (constructing and sending request
bodies far exceeding the target's expected size) is out of scope for this
harness -- it is implemented by the vector-implementation agent, reusing an
existing generic load tool (k6, mcp-server-fuzzer, or similar) per
implementation-plan.txt Phase 4, which explicitly says not to build a
bespoke flooder here. This file only registers metadata + the config
surface so `dos_module.cli` can enumerate/select the vector and so the
vector-implementation agent has a concrete class to fill in.

Mitigation counterpart (Phase 4): request body size cap.
"""
from __future__ import annotations

from ..interface import AttackContext, AttackModule, AttackOutcome, Transport
from ..registry import register_module


@register_module("oversized_body")
class OversizedBodyModule(AttackModule):
    cwe = "CWE-770"
    description = (
        "Send request bodies far exceeding the target's expected/documented "
        "size to exhaust parsing time and/or memory."
    )
    supported_transports = (Transport.STREAMABLE_HTTP, Transport.SSE, Transport.STDIO)

    def run(self, ctx: AttackContext) -> AttackOutcome:
        self.validate_context(ctx)
        raise NotImplementedError(
            "oversized_body load generation is the vector-implementation "
            "agent's responsibility; this scaffold only wires up "
            "config/registry/results plumbing. See harness/REPORT.md."
        )
