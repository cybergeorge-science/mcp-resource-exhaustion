"""Table 6 per-run JSON record schema (paper Section 5.2 / implementation-
plan.txt Phase 3).

Field list is exactly as specified in implementation-plan.txt:
    run_id, vector, load_level, concurrency, mitigation, peak_rss_mb,
    mean_cpu_pct, lat_p50_ms, lat_p95_ms, lat_p99_ms, error_rate,
    time_to_oom_s (nullable), recovery_s (nullable), amplification,
    ts_start, ts_end (iso8601)

Table 6b addition (paper Section 5.2, "Honest note on schema drift"):
`transport`, `sdk`, and `is_synthetic` were added after the experiments
work demonstrated they are needed for a real multi-transport, multi-SDK,
hybrid real/synthetic dataset -- `experiments/results/all_results.json`
carries all three on every row. They are added here as OPTIONAL
(nullable, not in `required`) rather than mandatory fields, specifically
so this change stays backward compatible with every existing caller/test
that predates it (none of which set them) while still letting
`additionalProperties: false` validate real experiments data without
rejecting it. A future release that wants these mandatory should move
them into `required` and update every caller in the same change.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

RUN_RECORD_JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DoS measurement run record (paper Table 6)",
    "type": "object",
    "required": [
        "run_id",
        "vector",
        "load_level",
        "concurrency",
        "mitigation",
        "peak_rss_mb",
        "mean_cpu_pct",
        "lat_p50_ms",
        "lat_p95_ms",
        "lat_p99_ms",
        "error_rate",
        "time_to_oom_s",
        "recovery_s",
        "amplification",
        "ts_start",
        "ts_end",
    ],
    "properties": {
        "run_id": {"type": "string"},
        "vector": {"type": "string"},
        "load_level": {"type": ["number", "null"]},
        "concurrency": {"type": "integer", "minimum": 1},
        "mitigation": {"type": "boolean"},
        "peak_rss_mb": {"type": ["number", "null"]},
        "mean_cpu_pct": {"type": ["number", "null"]},
        "lat_p50_ms": {"type": ["number", "null"]},
        "lat_p95_ms": {"type": ["number", "null"]},
        "lat_p99_ms": {"type": ["number", "null"]},
        "error_rate": {"type": "number", "minimum": 0, "maximum": 1},
        "time_to_oom_s": {"type": ["number", "null"]},
        "recovery_s": {"type": ["number", "null"]},
        "amplification": {"type": ["number", "null"]},
        # ts_start/ts_end accept EITHER an ISO-8601 date-time string (the
        # harness's own results_writer.utc_now_iso() convention) OR a numeric
        # Unix-epoch timestamp (the experiments pipeline's time.time()
        # convention, on which common/synth_model.py performs float
        # arithmetic). Relaxing to a string|number union -- rather than
        # rewriting 3,944 rows or breaking the synth model's arithmetic --
        # is the project-wide reconciliation of the type drift flagged in
        # paper Sec. 5.2. `format` is annotation-only and applies to strings.
        "ts_start": {"type": ["string", "number"], "format": "date-time"},
        "ts_end": {"type": ["string", "number"], "format": "date-time"},
        # Table 6b additions -- optional, not required (see module docstring).
        "transport": {"type": ["string", "null"], "enum": ["http", "stdio", "sse", None]},
        "sdk": {"type": ["string", "null"], "enum": ["python", "typescript", None]},
        "is_synthetic": {"type": ["boolean", "null"]},
        # Traceability fields carried by the experiments dataset. Declared
        # here as OPTIONAL so the full all_results.json validates under
        # additionalProperties:false (previously these lived deliberately
        # outside the schema, which meant the dataset could not be validated
        # against it -- resolved during the P2.1 pass).
        "anchor_run_id": {"type": ["string", "null"]},
        "notes": {"type": ["string", "null"]},
        "rep_index": {"type": ["integer", "null"]},
        "cell_id": {"type": ["string", "null"]},
        "benign_latencies_ms": {"type": ["array", "null"],
                                "items": {"type": "number"}},
    },
    "additionalProperties": False,
}


@dataclass
class RunRecord:
    run_id: str
    vector: str
    load_level: Optional[float]
    concurrency: int
    mitigation: bool
    peak_rss_mb: Optional[float]
    mean_cpu_pct: Optional[float]
    lat_p50_ms: Optional[float]
    lat_p95_ms: Optional[float]
    lat_p99_ms: Optional[float]
    error_rate: float
    time_to_oom_s: Optional[float]
    recovery_s: Optional[float]
    amplification: Optional[float]
    ts_start: object  # ISO-8601 string OR numeric Unix epoch (see schema note)
    ts_end: object
    # Table 6b additions (optional, default None -- see module docstring):
    transport: Optional[str] = None
    sdk: Optional[str] = None
    is_synthetic: Optional[bool] = None
    # Traceability fields (optional, default None -- see schema note):
    anchor_run_id: Optional[str] = None
    notes: Optional[str] = None
    rep_index: Optional[int] = None
    cell_id: Optional[str] = None
    benign_latencies_ms: Optional[list] = None

    def to_dict(self) -> dict:
        return asdict(self)
