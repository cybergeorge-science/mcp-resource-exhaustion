"""Config loading + validation for dos_module run configs (Listing 1).

ASSUMED INTERFACE -- see interface.py's docstring / harness/REPORT.md: no
upstream MCPSecBench config-loading equivalent exists.

Validates a run.yaml (see configs/run.example.yaml) against
configs/config.schema.json, then applies a few semantic checks that JSON
Schema cannot express cleanly (loopback-only host enforcement, known vector
ids). Both checks are deliberately duplicated with the schema's `enum`
constraints (belt-and-suspenders): the schema keeps a hand-edited file
honest, this function keeps a programmatically-built config dict honest too.
"""
from __future__ import annotations

import json
import os
from typing import Any

import jsonschema
import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCHEMA_PATH = os.path.join(_HERE, "configs", "config.schema.json")

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

KNOWN_VECTOR_IDS = {
    "oversized_body",
    "init_session_flood",
    "unbounded_stdio_stream",
    "deeply_nested_json",
    "tool_invocation_flooding",
    "slow_sse_slow_read",
    "redos_input_validation",
}


class ConfigError(ValueError):
    """Raised for both schema violations and harness-specific semantic
    violations (e.g. non-loopback host) so callers can catch one type."""


def load_schema() -> dict:
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_config(path: str) -> dict:
    """Load a YAML run config from disk and validate it. Raises
    ConfigError (schema or semantic) or FileNotFoundError."""
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    validate_config(cfg)
    return cfg


def validate_config(cfg: dict[str, Any]) -> None:
    schema = load_schema()
    try:
        jsonschema.validate(instance=cfg, schema=schema)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"schema validation failed: {exc.message}") from exc

    host = cfg.get("target", {}).get("host")
    if host not in LOOPBACK_HOSTS:
        raise ConfigError(
            f"target.host={host!r} is not loopback; this harness is "
            f"localhost-only by design (no code here targets non-loopback "
            f"addresses by default)"
        )

    for v in cfg.get("vectors", []):
        vid = v.get("id")
        if vid not in KNOWN_VECTOR_IDS:
            raise ConfigError(
                f"unknown vector id in config: {vid!r}; known: {sorted(KNOWN_VECTOR_IDS)}"
            )
