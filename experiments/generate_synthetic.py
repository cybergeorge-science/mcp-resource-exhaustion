"""
Generates the synthetic full-sweep dataset for all 7 vectors from the real
smoke-test anchors in results/real/*.json, using common/synth_model.py.
Writes results/synthetic/<vector>.json (is_synthetic=True rows only) and
results/all_results.json (real + synthetic combined).

Since P1.1, each vector's primary results/real/<vector>.json holds MANY
replicated real rows (>=5 reps x {OFF,ON}) rather than a single OFF/ON pair,
and a P1.2 second load point may live in results/real/<vector>__anchor2.json.
The synthetic sweep is seeded from the PER-CELL MEAN of the primary anchor's
kept reps (warm-ups excluded) -- a more robust anchor than any single run --
while EVERY individual real rep row (primary + anchor2) is carried through to
all_results.json unchanged (is_synthetic=False). The mean is used only to seed
the model; it is never written as if it were an observation.

Run after each vector's run_smoke.py (and, for P1.2, run_replication.py
--anchor2) have produced results/real/*.json.
"""
import glob
import json
import os
from statistics import mean

from common.schema import Record, write_records
from common.synth_model import generate_for_vector

ROOT = os.path.dirname(os.path.abspath(__file__))


def _row_to_record(d: dict) -> Record:
    return Record(**{k: v for k, v in d.items() if k in Record.__dataclass_fields__})


def load_rows(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def kept_reps(rows: list[dict], mitigation: bool) -> list[dict]:
    return [r for r in rows if not r.get("is_synthetic")
            and bool(r["mitigation"]) is mitigation
            and (r.get("rep_index") is None or r["rep_index"] >= 0)]


def mean_anchor(rows: list[dict], mitigation: bool) -> Record:
    reps = kept_reps(rows, mitigation)
    if not reps:
        raise ValueError(f"no kept reps for mitigation={mitigation}")

    def m(field):
        vals = [r[field] for r in reps if r.get(field) is not None]
        return mean(vals) if vals else 0.0

    ref = reps[0]
    ts_start = ref["ts_start"]
    dur = mean([r["ts_end"] - r["ts_start"] for r in reps])
    return Record(
        vector=ref["vector"], transport=ref.get("transport"), sdk=ref.get("sdk"),
        load_level=ref["load_level"], concurrency=ref["concurrency"],
        mitigation=mitigation,
        peak_rss_mb=m("peak_rss_mb"), mean_cpu_pct=m("mean_cpu_pct"),
        lat_p50_ms=m("lat_p50_ms"), lat_p95_ms=m("lat_p95_ms"), lat_p99_ms=m("lat_p99_ms"),
        error_rate=m("error_rate"),
        time_to_oom_s=None, recovery_s=m("recovery_s"), amplification=m("amplification"),
        ts_start=ts_start, ts_end=ts_start + dur, is_synthetic=False,
        run_id=ref["run_id"],  # point synthetic anchor_run_id at a real rep
        notes=f"MEAN-of-{len(reps)}-reps anchor (seed only; not written as a row)",
    )


def main():
    primary_files = sorted(
        p for p in glob.glob(os.path.join(ROOT, "results", "real", "*.json"))
        if "__" not in os.path.basename(p))
    if not primary_files:
        raise SystemExit("no results/real/*.json found -- run run_replication.py first")

    all_records: list[Record] = []
    for path in primary_files:
        vector = os.path.splitext(os.path.basename(path))[0]
        rows = load_rows(path)
        # carry through every real rep row (primary anchor)
        all_records.extend(_row_to_record(d) for d in rows)
        # carry through the P1.2 second-anchor reps, if present
        p2 = os.path.join(ROOT, "results", "real", f"{vector}__anchor2.json")
        if os.path.exists(p2):
            all_records.extend(_row_to_record(d) for d in load_rows(p2))

        # seed synthetic sweep from the per-cell MEAN of the primary anchor
        anchor_off = mean_anchor(rows, mitigation=False)
        anchor_on = mean_anchor(rows, mitigation=True)
        synth = generate_for_vector(vector, anchor_off, anchor_on)
        write_records(synth, os.path.join(ROOT, "results", "synthetic", f"{vector}.json"))
        all_records.extend(synth)

    write_records(all_records, os.path.join(ROOT, "results", "all_results.json"))
    n_real = sum(1 for r in all_records if not r.is_synthetic)
    n_synth = sum(1 for r in all_records if r.is_synthetic)
    print(f"TOTAL: {n_real} real rows, {n_synth} synthetic rows, {len(all_records)} combined "
          f"-> results/all_results.json")


if __name__ == "__main__":
    main()
