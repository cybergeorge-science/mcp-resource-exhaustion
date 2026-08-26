"""
Validate experiments/results/all_results.json against the harness's locked
RUN_RECORD_JSON_SCHEMA (paper Table 6). Acceptance gate for P2.1.

Exit code 0 and "OK" iff every row validates with zero errors.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))
HARNESS = os.path.abspath(os.path.join(ROOT, "..", "harness"))
sys.path.insert(0, HARNESS)

from measure.schema import RUN_RECORD_JSON_SCHEMA  # noqa: E402
import jsonschema  # noqa: E402


def main(path: str | None = None) -> int:
    path = path or os.path.join(ROOT, "results", "all_results.json")
    with open(path, encoding="utf-8") as fh:
        rows = json.load(fh)
    validator = jsonschema.Draft202012Validator(RUN_RECORD_JSON_SCHEMA)
    n_err = 0
    for i, row in enumerate(rows):
        for err in validator.iter_errors(row):
            n_err += 1
            if n_err <= 20:
                print(f"row {i} ({row.get('run_id','?')}): {err.message}")
    n_real = sum(1 for r in rows if not r.get("is_synthetic"))
    n_syn = len(rows) - n_real
    print(f"validated {len(rows)} rows ({n_real} real, {n_syn} synthetic) "
          f"against RUN_RECORD_JSON_SCHEMA")
    if n_err == 0:
        print("OK: zero schema errors")
        return 0
    print(f"FAIL: {n_err} schema error(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
