"""
P1.2 model validation: predicted-vs-measured residuals at the SECOND real load
point.

The synthetic power-law sweep is seeded from the PRIMARY anchor only. This
script checks it against the independently-measured second load point
(load_index = anchor + 1), which the model did NOT see. For each vector it
compares, at the second-anchor cell (anchor transport/sdk/concurrency):

  * MEASURED = mean over the real reps in results/real/<vector>__anchor2.json
    (carried into all_results.json, is_synthetic=false)
  * PREDICTED = mean over the synthetic sweep rows the model produced at that
    exact cell (is_synthetic=true)

and reports the signed % residual per dependent variable. Because PREDICTED is
read straight from the committed sweep rows (not a re-derivation), the residual
reflects the published model, not an approximation of it.

Writes results/model_validation.json and prints a residual table.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from common.grid import ANCHOR_LOAD_INDEX, REAL_ANCHOR  # noqa: E402

ROOT = os.path.abspath(os.path.dirname(__file__))
DVS = ["peak_rss_mb", "mean_cpu_pct", "lat_p95_ms", "error_rate"]


def mean_field(rows, field):
    vals = [r[field] for r in rows if r.get(field) is not None]
    return sum(vals) / len(vals) if vals else None


def main():
    with open(os.path.join(ROOT, "results", "all_results.json"), encoding="utf-8") as fh:
        rows = json.load(fh)

    out = []
    for vector, aidx in ANCHOR_LOAD_INDEX.items():
        second = aidx + 1
        anchor = REAL_ANCHOR[vector]
        tr, sdk = anchor["transport"], anchor["sdk"]
        # anchor concurrency = the concurrency the real reps used
        real_second = [r for r in rows if r["vector"] == vector and not r["is_synthetic"]
                       and r["load_level"] == second
                       and (r.get("rep_index") is None or r["rep_index"] >= 0)]
        if not real_second:
            continue
        conc = real_second[0]["concurrency"]
        for mit in (False, True):
            measured = [r for r in real_second if bool(r["mitigation"]) is mit]
            predicted = [r for r in rows if r["is_synthetic"] and r["vector"] == vector
                         and r.get("transport") == tr and r.get("sdk") == sdk
                         and r["load_level"] == second and r["concurrency"] == conc
                         and bool(r["mitigation"]) is mit]
            if not measured or not predicted:
                continue
            entry = {"vector": vector, "load_level": second, "concurrency": conc,
                     "mitigation": mit, "n_measured": len(measured),
                     "n_predicted": len(predicted)}
            for dv in DVS:
                m = mean_field(measured, dv)
                p = mean_field(predicted, dv)
                entry[dv] = {"measured": m, "predicted": p}
                if m is not None and p is not None and abs(m) > 1e-9:
                    entry[dv]["residual_pct"] = round(100.0 * (p - m) / m, 1)
                else:
                    entry[dv]["residual_pct"] = None
            out.append(entry)

    with open(os.path.join(ROOT, "results", "model_validation.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"{'vector':<20} {'mit':<4} {'DV':<14} {'measured':>12} {'predicted':>12} {'resid%':>8}")
    for e in out:
        for dv in DVS:
            d = e[dv]
            m = f"{d['measured']:.2f}" if d['measured'] is not None else "n/a"
            p = f"{d['predicted']:.2f}" if d['predicted'] is not None else "n/a"
            rp = f"{d['residual_pct']:+.1f}" if d['residual_pct'] is not None else "n/a"
            print(f"{e['vector']:<20} {'ON' if e['mitigation'] else 'OFF':<4} {dv:<14} {m:>12} {p:>12} {rp:>8}")
    print("\nwrote results/model_validation.json")


if __name__ == "__main__":
    main()
