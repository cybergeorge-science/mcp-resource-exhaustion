"""Importing this package registers all 7 in-scope DoS vector stubs with
dos_module.registry. Each stub is metadata + a NotImplementedError body;
actual load generation is implemented by the vector-implementation agent
(implementation-plan.txt Phase 4). This package exists so that
`dos_module.cli --list` and config validation have concrete, importable
classes to point at from day one.
"""
from . import (  # noqa: F401  (imported for registration side effects)
    oversized_body,
    init_session_flood,
    unbounded_stdio_stream,
    deeply_nested_json,
    tool_invocation_flooding,
    slow_sse_slow_read,
    redos_input_validation,
)

__all__ = [
    "oversized_body",
    "init_session_flood",
    "unbounded_stdio_stream",
    "deeply_nested_json",
    "tool_invocation_flooding",
    "slow_sse_slow_read",
    "redos_input_validation",
]
