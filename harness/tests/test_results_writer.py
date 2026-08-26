"""Smoke tests for measure.results_writer / measure.schema on synthetic
sampler + latency data -- no MCP server."""
import json
import os

import jsonschema
import pytest

from measure.benign_client import BenignClient, BenignClientConfig
from measure.results_writer import (
    append_jsonl,
    build_run_record,
    compute_amplification,
    compute_recovery_s,
    read_jsonl,
    utc_now_iso,
    validate_run_record,
    write_json,
)
from measure.sampler import ResourceSampler, ResourceSamplerConfig
from measure.schema import RUN_RECORD_JSON_SCHEMA


def _synthetic_sampler_and_latency(pid):
    import time

    sampler = ResourceSampler(pid, ResourceSamplerConfig(interval_s=0.05))
    sampler.start()

    def fake_request():
        pass

    client = BenignClient(fake_request, BenignClientConfig(rate_hz=20, duration_s=0.2))
    client.run_for()
    time.sleep(0.1)
    sampler.stop()
    return sampler, client.recorder


def test_build_run_record_produces_a_schema_valid_record():
    import os as _os

    sampler, latency = _synthetic_sampler_and_latency(_os.getpid())
    ts_start = utc_now_iso()
    ts_end = utc_now_iso()

    record = build_run_record(
        run_id="test-run-0001",
        vector="oversized_body",
        load_level=4.0,
        concurrency=8,
        mitigation=False,
        sampler=sampler,
        latency=latency,
        ts_start=ts_start,
        ts_end=ts_end,
        time_to_oom_s=None,
        recovery_s=None,
        amplification=None,
    )

    validate_run_record(record)  # should not raise
    d = record.to_dict()
    assert d["vector"] == "oversized_body"
    assert d["concurrency"] == 8
    assert d["mitigation"] is False
    assert d["peak_rss_mb"] > 0
    assert 0.0 <= d["error_rate"] <= 1.0


def test_build_run_record_handles_none_sampler_and_latency_gracefully():
    record = build_run_record(
        run_id="test-run-0002",
        vector="init_session_flood",
        load_level=None,
        concurrency=1,
        mitigation=True,
        sampler=None,
        latency=None,
        ts_start=utc_now_iso(),
        ts_end=utc_now_iso(),
    )
    validate_run_record(record)
    d = record.to_dict()
    assert d["peak_rss_mb"] is None
    assert d["lat_p50_ms"] is None
    assert d["error_rate"] == 0.0


def test_write_json_round_trips_and_validates(tmp_path):
    record = build_run_record(
        run_id="test-run-0003",
        vector="deeply_nested_json",
        load_level=1000,
        concurrency=1,
        mitigation=False,
        sampler=None,
        latency=None,
        ts_start=utc_now_iso(),
        ts_end=utc_now_iso(),
    )
    out_path = tmp_path / "run.json"
    write_json(record, str(out_path))

    with open(out_path, "r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    jsonschema.validate(instance=loaded, schema=RUN_RECORD_JSON_SCHEMA)
    assert loaded["run_id"] == "test-run-0003"


def test_append_jsonl_and_read_jsonl_round_trip(tmp_path):
    out_path = tmp_path / "results" / "run.jsonl"
    for i in range(3):
        record = build_run_record(
            run_id=f"test-run-jsonl-{i}",
            vector="tool_invocation_flooding",
            load_level=float(i),
            concurrency=1,
            mitigation=False,
            sampler=None,
            latency=None,
            ts_start=utc_now_iso(),
            ts_end=utc_now_iso(),
        )
        append_jsonl(record, str(out_path))

    records = read_jsonl(str(out_path))
    assert len(records) == 3
    assert [r["run_id"] for r in records] == [f"test-run-jsonl-{i}" for i in range(3)]


def test_invalid_record_fails_schema_validation():
    from measure.schema import RunRecord

    bad = RunRecord(
        run_id="bad",
        vector="oversized_body",
        load_level=1,
        concurrency=1,
        mitigation=False,
        peak_rss_mb=None,
        mean_cpu_pct=None,
        lat_p50_ms=None,
        lat_p95_ms=None,
        lat_p99_ms=None,
        error_rate=1.5,  # out of [0,1] range -> must fail schema validation
        time_to_oom_s=None,
        recovery_s=None,
        amplification=None,
        ts_start=utc_now_iso(),
        ts_end=utc_now_iso(),
    )
    with pytest.raises(jsonschema.ValidationError):
        validate_run_record(bad)


def test_compute_amplification_formula_and_edge_cases():
    assert compute_amplification(target_cost=100.0, attacker_cost=10.0) == 10.0
    assert compute_amplification(target_cost=None, attacker_cost=10.0) is None
    assert compute_amplification(target_cost=100.0, attacker_cost=0.0) is None
    assert compute_amplification(target_cost=100.0, attacker_cost=None) is None


def test_compute_recovery_s_finds_threshold_crossing():
    baseline_p95 = 100.0  # ms
    attack_stop_ts = 1000.0
    # still degraded at +1s, recovers (<=110% of baseline) at +3s
    timeline = [
        (1001.0, 400.0),
        (1002.0, 250.0),
        (1003.0, 105.0),  # <= 110.0 -> recovered here
        (1004.0, 100.0),
    ]
    recovery_s = compute_recovery_s(timeline, baseline_p95, attack_stop_ts, threshold_pct=110.0)
    assert recovery_s == pytest.approx(3.0)


def test_compute_recovery_s_returns_none_when_never_recovers_within_max_wait():
    baseline_p95 = 100.0
    attack_stop_ts = 0.0
    timeline = [(10.0, 500.0), (30.0, 400.0), (61.0, 300.0)]
    recovery_s = compute_recovery_s(
        timeline, baseline_p95, attack_stop_ts, threshold_pct=110.0, max_wait_s=60.0
    )
    assert recovery_s is None
