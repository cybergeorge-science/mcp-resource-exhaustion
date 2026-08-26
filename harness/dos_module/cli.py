"""CLI entry point for the DoS/availability module.

Usage:
    python -m dos_module.cli --list
    python -m dos_module.cli --config run.yaml --dry-run
    python -m dos_module.cli --config run.yaml

ASSUMED INTERFACE -- see dos_module/interface.py's module docstring and
harness/REPORT.md: no upstream MCPSecBench CLI equivalent exists to match.

This CLI deliberately does NOT execute attack traffic -- see
implementation-plan.txt Phase 4 / dos_module/vectors/*.py: load generation
belongs to a separate agent. `--list` and `--dry-run` are fully functional
today (they exercise the real registry + config validation code); actually
running a cell requires a real target process to attach the resource
sampler to, plus a concrete AttackModule.run() implementation, both of
which are out of this harness's scope.
"""
from __future__ import annotations

import argparse
import sys
from typing import Any

from . import vectors  # noqa: F401  (import populates the registry via side effects)
from .config import ConfigError, load_config
from .registry import get_module, list_modules


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m dos_module.cli",
        description="DoS/availability measurement module CLI (scaffold).",
    )
    parser.add_argument("--config", "-c", help="Path to a run YAML config (Listing 1 schema).")
    parser.add_argument("--list", action="store_true", help="List registered vector modules and exit.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the config and print the resolved run plan (expanded vector x load_level x concurrency cells) without executing anything.",
    )
    return parser


def resolve_plan(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand the vectors/load_levels/concurrency matrix in a validated
    config dict into individual run cells. Pure function, no I/O, so it is
    unit-testable on its own (see tests/test_cli.py)."""
    plan: list[dict[str, Any]] = []
    repetitions = cfg.get("run", {}).get("repetitions", 1)
    for v in cfg.get("vectors", []):
        if not v.get("enabled", True):
            continue
        load_levels = v.get("load_levels") or [None]
        concurrency_levels = v.get("concurrency") or [1]
        for load_level in load_levels:
            for concurrency in concurrency_levels:
                plan.append(
                    {
                        "vector_id": v["id"],
                        "load_level": load_level,
                        "concurrency": concurrency,
                        "mitigation": v.get("mitigation", False),
                        "repetitions": repetitions,
                    }
                )
    return plan


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.list:
        for vector_id in list_modules():
            mod = get_module(vector_id)
            print(f"{vector_id}\t{mod.cwe}\t{mod.description}")
        return 0

    if not args.config:
        print("error: --config is required unless --list is given", file=sys.stderr)
        return 2

    try:
        cfg = load_config(args.config)
    except (ConfigError, FileNotFoundError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    plan = resolve_plan(cfg)
    for cell in plan:
        print(cell)
    print(f"resolved {len(plan)} run cell(s) from {args.config}", file=sys.stderr)

    if args.dry_run:
        print("[dry-run] no attack traffic sent.", file=sys.stderr)
        return 0

    print(
        "This scaffold does not execute attack traffic itself -- vector "
        "load-generation implementations are out of scope for this harness "
        "(see harness/REPORT.md). Wire a concrete AttackModule.run() per "
        "vector and drive measure.sampler / measure.benign_client / "
        "measure.results_writer around it to execute cells for real.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
