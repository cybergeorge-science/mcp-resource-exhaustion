"""
Python-SDK reference server (stdio transport) used by vector 7
(ReDoS in input validation).

REAL official `mcp` package, FastMCP, stdio transport (newline-delimited
JSON-RPC over stdin/stdout, exactly as implemented by
mcp.server.stdio.stdio_server -- see that module for the framing this
server relies on).

Exposes:
  - echo(text)      benign tool, used for latency probing
  - validate(text)  DELIBERATELY vulnerable to catastrophic backtracking:
                     matches text against ^(a+)+$ -- classic ReDoS pattern
                     (CWE-1333). Cost is exponential in the number of
                     leading 'a's when the string fails to match (e.g. a
                     trailing non-'a' character forces the engine to
                     explore all groupings of the '(a+)+' before giving up).

Mitigation (env var MIT_MAX_INPUT_LEN, default "0" = off): a practical
"safe regex" hardening -- reject any input longer than the cap BEFORE the
vulnerable pattern is ever evaluated, so catastrophic backtracking never
starts. (A true per-call evaluation timeout would need a killable worker
process/thread, which the CPython `re` engine cannot be preempted from
mid-match without one; that's noted as a limitation in REPORT.md rather
than half-implemented here.)

READY marker + all diagnostic prints go to STDERR, never stdout -- stdout
is reserved exclusively for the JSON-RPC stream once the transport takes
over.
"""
from __future__ import annotations

import os
import re
import sys

from mcp.server.fastmcp import FastMCP

MIT_MAX_INPUT_LEN = int(os.environ.get("MIT_MAX_INPUT_LEN", "0"))

VULNERABLE_PATTERN = re.compile(r"^(a+)+$")

mcp = FastMCP("dos-research-reference-server-stdio")


@mcp.tool()
def echo(text: str) -> str:
    """Trivial benign tool used to measure legitimate-client latency."""
    return text


@mcp.tool()
def validate(text: str) -> str:
    """Validates `text` against a (deliberately vulnerable) username-like
    pattern. If MIT_MAX_INPUT_LEN > 0, inputs longer than the cap are
    rejected before the vulnerable regex ever runs."""
    if MIT_MAX_INPUT_LEN > 0 and len(text) > MIT_MAX_INPUT_LEN:
        return f"rejected: input longer than {MIT_MAX_INPUT_LEN} chars (mitigation=safe_input_cap)"
    m = VULNERABLE_PATTERN.match(text)
    return "valid" if m else "invalid"


if __name__ == "__main__":
    print(f"READY pid={os.getpid()}", file=sys.stderr, flush=True)
    mcp.run(transport="stdio")
