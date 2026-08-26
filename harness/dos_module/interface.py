"""Common attack-module interface for the DoS/availability measurement module.

ASSUMED INTERFACE -- verify against real MCPSecBench source before merging.

We fetched the actual upstream repository (https://github.com/AIS2Lab/MCPSecBench,
cloned 2026-08-16) and inspected it directly rather than guessing. It does
NOT define a plugin/module-registry architecture, an AttackModule base
class, config-driven vector selection, or a machine-readable per-run results
schema. Its real structure is a flat set of standalone scripts:

    code/main.py            - orchestrator: drives Claude Desktop / Cursor via
                               pyautogui + pwntools, feeds prompts from
                               data/data.json, asks the LLM under test to
                               self-report "Attack success" / "Attack
                               detected" / "Protect Success", and writes
                               those codes (1 / 0 / -1 / 2) to a CSV
                               (data/experiments.csv).
    code/client.py           - a client that talks to an MCP host + server
                               (supports OpenAI, Claude).
    code/mitm.py             - a standalone Man-in-the-Middle script.
    code/squatting.py,
    code/maliciousadd.py,
    code/cve-2025-6514.py    - standalone malicious MCP servers, one per
                               attack, each a separate importless script.
    code/index.js            - a standalone DNS-rebinding script.

There is no "vectors/" directory, no base class, no config YAML/JSON, no
notion of transport/load-level/concurrency, and no latency- or
resource-based metrics anywhere in that codebase -- because MCPSecBench
evaluates agent/LLM-level attack surfaces (prompt injection, tool
poisoning, package-name squatting, rug pull, sandbox escape, MITM, DNS
rebinding, confused-deputy tool misuse, ...), judged by asking the LLM to
self-report success, not protocol-level availability/DoS attacks measured
by resource and latency instrumentation. See harness/REPORT.md for the
full comparison and quoted source excerpts.

Because there is nothing upstream to "match precisely" for a DoS module,
everything in this file is a clean, conventional plugin design instead:
an ABC + dataclass contract, analogous to what a mature benchmark's plugin
system would look like, but NOT verified against any authoritative source.
Treat it as a proposal for how a DoS/availability module *would* integrate
if MCPSecBench grows a real module system, not as a description of
existing MCPSecBench internals.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Sequence


class Transport(str, Enum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"
    SSE = "sse"


class Sdk(str, Enum):
    PYTHON = "python"
    TYPESCRIPT = "typescript"


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class AttackContext:
    """Everything one vector module needs to run a single
    (load_level, concurrency, mitigation) cell.

    This is what the vector-implementation agent's `AttackModule.run()`
    receives. It is deliberately load-generation-agnostic: this harness
    does not ship a flooder (implementation-plan.txt Phase 4 explicitly
    scopes load generation to a separate agent, reusing existing generic
    tools such as k6 or mcp-server-fuzzer). `extra` carries any
    vector-specific knobs declared in the YAML config's `vectors[].extra`.
    """

    run_id: str
    vector_id: str
    sdk: Sdk
    transport: Transport
    host: str  # must be loopback; enforced in AttackModule.validate_context and dos_module/config.py
    port: Optional[int]
    server_command: Optional[Sequence[str]]  # argv used to launch the target for stdio
    load_level: float
    concurrency: int
    mitigation: bool
    duration_s: float
    extra: dict = field(default_factory=dict)


@dataclass
class AttackOutcome:
    """What a vector module hands back to the harness after running one cell.

    The vector module owns driving its own load generator against the
    target and reporting what happened. The harness (harness/measure/)
    owns sampling resource usage and benign-client latency concurrently,
    and folds both sides into the Table 6 RunRecord
    (see harness/measure/schema.py and harness/measure/results_writer.py).
    """

    started_ok: bool
    attacker_request_count: int = 0
    attacker_bytes_sent: int = 0
    target_crashed: bool = False
    time_to_oom_s: Optional[float] = None
    notes: str = ""


class AttackModule(ABC):
    """Base class every DoS vector plugs into.

    Subclasses register themselves via `dos_module.registry.register_module`
    and are looked up by `vector_id` string from the YAML config. Concrete
    load generation is intentionally NOT implemented in this scaffold --
    that is the vector-implementation agent's job. `run()` here only
    validates the context and documents the contract; real subclasses
    replace the NotImplementedError body with actual attack traffic
    generation (typically shelling out to an existing tool per Phase 4).
    """

    vector_id: str = ""
    cwe: str = ""
    description: str = ""
    supported_transports: tuple[Transport, ...] = ()

    @abstractmethod
    def run(self, ctx: AttackContext) -> AttackOutcome:
        """Execute one (load_level, concurrency, mitigation) cell.

        Contract with the harness:
          - Called AFTER the harness has started the resource sampler and
            benign client for this cell (see measure/sampler.py,
            measure/benign_client.py) and BEFORE it stops them.
          - Must run for approximately `ctx.duration_s` seconds (or return
            promptly with `started_ok=False` if it could not start).
          - Must not touch any non-loopback host/port -- see
            `validate_context` below, which every subclass must call first.
        """
        raise NotImplementedError

    def validate_context(self, ctx: AttackContext) -> None:
        """Shared safety + sanity checks every subclass should call at the
        top of `run()`. Raises ValueError on violation."""
        if self.supported_transports and ctx.transport not in self.supported_transports:
            raise ValueError(
                f"{self.vector_id!r} does not support transport {ctx.transport!r}; "
                f"supported: {[t.value for t in self.supported_transports]}"
            )
        if ctx.host not in _LOOPBACK_HOSTS:
            raise ValueError(
                f"refusing non-loopback host {ctx.host!r}: this harness is "
                f"localhost-only by design (no code here targets non-loopback "
                f"addresses by default)"
            )
