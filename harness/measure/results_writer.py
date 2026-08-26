"""Folds raw sampler + latency + timing data into a Table 6 RunRecord and
writes it as JSON (one file per run) or appends to a JSONL results file.

This is what the vector-implementation agent's per-cell glue code should
call once an attack cell finishes running::

    from measure.sampler import ResourceSampler, ResourceSamplerConfig
    from measure.benign_client import BenignClient, BenignClientConfig
    from measure.results_writer import build_run_record, append_jsonl, utc_now_iso

    sampler = ResourceSampler(target_pid, ResourceSamplerConfig(interval_s=0.1))
    client = BenignClient(my_mcp_request_fn, BenignClientConfig(rate_hz=10, duration_s=30))

    ts_start = utc_now_iso()
    sampler.start()
    client.start_background()
    outcome = my_attack_module.run(ctx)          # vector-implementation agent's code
    client.stop()
    sampler.stop()
    ts_end = utc_now_iso()

    record = build_run_record(
        run_id=ctx.run_id,
        vector=ctx.vector_id,
        load_level=ctx.load_level,
        concurrency=ctx.concurrency,
        mitigation=ctx.mitigation,
        sampler=sampler,
        latency=client.recorder,
        ts_start=ts_start,
        ts_end=ts_end,
        time_to_oom_s=outcome.time_to_oom_s,
        recovery_s=None,       # fill in from compute_recovery_s once a post-attack window is captured
        amplification=None,    # fill in from compute_amplification once cost units are measured
    )
    append_jsonl(record, "results/run.jsonl")
"""
from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import jsonschema

from .amplification import ratio as _amp_ratio
from .latency import LatencyRecorder
from .sampler import ResourceSampler
from .schema import RUN_RECORD_JSON_SCHEMA, RunRecord


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp, e.g. '2026-08-16T14:03:21.123456+00:00'."""
    return datetime.now(timezone.utc).isoformat()


def _nan_to_none(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    try:
        if math.isnan(value):
            return None
    except TypeError:
        pass
    return value


def compute_amplification(
    target_cost: Optional[float], attacker_cost: Optional[float]
) -> Optional[float]:
    """amplification = target resource cost / attacker cost.

    Both costs must be supplied in caller-chosen but FIXED and documented
    units (see configs/run.example.yaml's `amplification.*_cost_unit`
    fields -- e.g. target_cost in CPU-ms consumed by the target process,
    attacker_cost in bytes sent or requests issued by the attack traffic).
    Returns None if either cost is missing or attacker_cost is 0, so a
    missing/undefined amplification is distinguishable from a genuine
    "zero-cost attacker" edge case in the RunRecord (both would otherwise
    look like division errors).

    Delegates to the single canonical implementation in
    `measure.amplification.ratio` (P3.3 unification)."""
    return _amp_ratio(target_cost, attacker_cost)


def build_run_record(
    *,
    run_id: str,
    vector: str,
    load_level: Optional[float],
    concurrency: int,
    mitigation: bool,
    sampler: Optional[ResourceSampler],
    latency: Optional[LatencyRecorder],
    ts_start: str,
    ts_end: str,
    time_to_oom_s: Optional[float] = None,
    recovery_s: Optional[float] = None,
    amplification: Optional[float] = None,
    transport: Optional[str] = None,
    sdk: Optional[str] = None,
    is_synthetic: Optional[bool] = None,
) -> RunRecord:
    """Fold a ResourceSampler + LatencyRecorder (or None, e.g. for a cell
    that failed to start) into one Table 6 RunRecord.

    `transport`/`sdk`/`is_synthetic` are the Table 6b additions (Section
    5.2's "Honest note on schema drift") -- optional, default None, so
    every pre-existing caller keeps working unchanged."""
    res_summary = (
        sampler.summary()
        if sampler is not None
        else {"peak_rss_mb": None, "mean_cpu_pct": None}
    )
    lat_summary = (
        latency.summary()
        if latency is not None
        else {"lat_p50_ms": None, "lat_p95_ms": None, "lat_p99_ms": None, "error_rate": 0.0}
    )
    return RunRecord(
        run_id=run_id,
        vector=vector,
        load_level=load_level,
        concurrency=concurrency,
        mitigation=mitigation,
        peak_rss_mb=_nan_to_none(res_summary.get("peak_rss_mb")),
        mean_cpu_pct=_nan_to_none(res_summary.get("mean_cpu_pct")),
        lat_p50_ms=_nan_to_none(lat_summary.get("lat_p50_ms")),
        lat_p95_ms=_nan_to_none(lat_summary.get("lat_p95_ms")),
        lat_p99_ms=_nan_to_none(lat_summary.get("lat_p99_ms")),
        error_rate=lat_summary.get("error_rate", 0.0),
        time_to_oom_s=time_to_oom_s,
        recovery_s=recovery_s,
        amplification=amplification,
        ts_start=ts_start,
        ts_end=ts_end,
        transport=transport,
        sdk=sdk,
        is_synthetic=is_synthetic,
    )


def validate_run_record(record: RunRecord) -> None:
    jsonschema.validate(instance=record.to_dict(), schema=RUN_RECORD_JSON_SCHEMA)


def write_json(record: RunRecord, path: str) -> None:
    """Write one RunRecord as a standalone, schema-validated JSON file."""
    validate_run_record(record)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record.to_dict(), fh, indent=2)


def append_jsonl(record: RunRecord, path: str) -> None:
    """Append one RunRecord as a schema-validated line to a JSONL results
    file (one run per line), the recommended format for a full sweep."""
    validate_run_record(record)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record.to_dict()))
        fh.write("\n")


def read_jsonl(path: str) -> List[dict]:
    """Read back a JSONL results file, validating each line against the
    Table 6 schema. Used by tests and by any downstream analysis script."""
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            jsonschema.validate(instance=obj, schema=RUN_RECORD_JSON_SCHEMA)
            records.append(obj)
    return records


def compute_recovery_s(
    latency_timeline: List[Tuple[float, float]],
    baseline_p95_ms: float,
    attack_stop_ts: float,
    threshold_pct: float = 110.0,
    max_wait_s: float = 60.0,
) -> Optional[float]:
    """Recovery time = seconds from attack stop until benign p95 latency
    first returns to <= threshold_pct% of baseline_p95_ms.

    `latency_timeline` is a list of (ts, latency_ms) points sampled AFTER
    attack_stop_ts -- typically a rolling p95 the caller computes over a
    sliding window of recent benign-request latencies. This function only
    performs the threshold-crossing search; rolling-window p95 computation
    is left to the caller since the window size is a policy choice, not
    measurement plumbing.

    threshold_pct defaults to 110% (recovered = benign p95 within 10% of
    its pre-attack baseline), per implementation-plan.txt Phase 3's
    requirement that this threshold be fixed and held constant across all
    runs. This default is this harness's PLACEHOLDER, not a value taken
    from any published source -- the paper's Section 4.2 must state its
    final chosen constant explicitly.

    Returns None (not 0, not float('inf')) if recovery is not observed
    within max_wait_s seconds of attack_stop_ts.
    """
    threshold_ms = baseline_p95_ms * (threshold_pct / 100.0)
    for ts, lat_ms in latency_timeline:
        if ts < attack_stop_ts:
            continue
        elapsed = ts - attack_stop_ts
        if lat_ms <= threshold_ms:
            return elapsed
        if elapsed > max_wait_s:
            return None
    return None
