"""Smoke tests for dos_module.cli -- exercises --list and --dry-run, which
are the only two modes that don't require a live target, per this
harness's scope (load generation is a different agent's job)."""
import os

from dos_module.cli import main, resolve_plan
from dos_module.config import load_config

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXAMPLE_CONFIG = os.path.join(
    _HERE, "..", "dos_module", "configs", "run.example.yaml"
)


def test_list_returns_zero_and_lists_all_seven_vectors(capsys):
    rc = main(["--list"])
    assert rc == 0
    out = capsys.readouterr().out
    for vector_id in (
        "oversized_body",
        "init_session_flood",
        "unbounded_stdio_stream",
        "deeply_nested_json",
        "tool_invocation_flooding",
        "slow_sse_slow_read",
        "redos_input_validation",
    ):
        assert vector_id in out


def test_missing_config_without_list_returns_nonzero():
    rc = main([])
    assert rc == 2


def test_dry_run_against_example_config_returns_zero(capsys):
    rc = main(["--config", _EXAMPLE_CONFIG, "--dry-run"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "dry-run" in err


def test_resolve_plan_expands_load_level_and_concurrency_matrix():
    cfg = load_config(_EXAMPLE_CONFIG)
    plan = resolve_plan(cfg)
    assert len(plan) > 0
    # oversized_body: 5 load_levels x 4 concurrency levels = 20 cells
    oversized_cells = [c for c in plan if c["vector_id"] == "oversized_body"]
    assert len(oversized_cells) == 5 * 4
    # unbounded_stdio_stream is disabled in the example config -> 0 cells
    stdio_cells = [c for c in plan if c["vector_id"] == "unbounded_stdio_stream"]
    assert len(stdio_cells) == 0
