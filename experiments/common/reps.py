"""
Replication runner (P1.1).

Wraps a vector driver's ``one_run(mitigation: bool) -> Record`` so that a
single ``run_smoke.py --reps N`` invocation:

  * runs N kept repetitions (+ 1 discarded warm-up rep) of BOTH mitigation
    states at the vector's existing anchor cell;
  * uses a FRESH server process per run (already the drivers' behaviour --
    each one_run() starts and kills its own server);
  * RANDOMIZES the OFF/ON order within every rep (seeded, reproducible);
  * DISCARDS the warm-up rep (persisted with rep_index = -1 and a note, so it
    is auditable but excluded from stats by common/stats.py);
  * COOLS DOWN a fixed interval between runs so RSS/thermal state resets;
  * on a harness error (server failed to start, attack crashed) LOGS and
    RE-RUNS that single run once, per the paper Sec. 4.4 outlier rule
    ("discard harness-error runs, log, re-run"), rather than persisting a
    broken row;
  * tags each persisted row with a shared ``cell_id`` and its ``rep_index``.

Every persisted row is a genuine measurement (is_synthetic=False); nothing
here fabricates or models a number.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import random
from typing import Callable

from common.schema import Record, write_records

DEFAULT_REPS = 10
DEFAULT_WARMUP = 1
DEFAULT_COOLDOWN_S = 2.0
DEFAULT_SEED = 20260816


def make_cell_id(rec: Record) -> str:
    return (f"{rec.vector}|{rec.transport}|{rec.sdk}|L{rec.load_level}"
            f"|C{rec.concurrency}|{'on' if rec.mitigation else 'off'}")


def run_reps(vector: str, one_run: Callable[..., Record], *,
             reps: int = DEFAULT_REPS, warmup: int = DEFAULT_WARMUP,
             cooldown_s: float = DEFAULT_COOLDOWN_S, seed: int = DEFAULT_SEED,
             max_retries: int = 1, control: bool = False) -> list[Record]:
    """Run `reps` kept + `warmup` discarded replicates and return all persisted
    rows.

    Normal mode (``control=False``): both mitigation states per rep, in
    randomized (seeded) order -- an *attack-present* mitigation-efficacy cell.

    Control mode (``control=True``): the NO-ATTACK baseline (paper Sec. 3
    success criterion). Each rep runs a single arm -- server up, benign probe
    running, the attack module NOT invoked (``one_run(False, no_attack=True)``).
    Mitigation state is irrelevant with no attack to mitigate, so only the
    server-as-shipped (mitigation off) arm is measured. Every row is still a
    genuine measurement; nothing here fabricates a number."""
    if reps < 5:
        print(f"[{vector}] WARNING: reps={reps} < 5 (paper minimum). Proceeding.",
              file=sys.stderr)
    rng = random.Random(seed)
    records: list[Record] = []
    total = reps + warmup
    for r in range(total):
        kept_index = r - warmup            # -1 == warm-up, 0..reps-1 == kept
        is_warmup = kept_index < 0
        if control:
            states = [False]               # no attack -> mitigation is moot
        else:
            states = [False, True]
            rng.shuffle(states)
        for mitigation in states:
            rec = None
            for attempt in range(max_retries + 1):
                try:
                    rec = one_run(mitigation, no_attack=control)
                    break
                except Exception as exc:  # harness error -> log + re-run
                    print(f"[{vector}] harness error on rep {kept_index} "
                          f"mit={mitigation} attempt {attempt}: {exc}",
                          file=sys.stderr)
                    time.sleep(cooldown_s)
            if rec is None:
                raise RuntimeError(
                    f"[{vector}] rep {kept_index} mit={mitigation} failed "
                    f"after {max_retries + 1} attempts")
            rec.rep_index = kept_index
            rec.cell_id = make_cell_id(rec) + ("|noattack" if control else "")
            tag = "WARMUP(discarded)" if is_warmup else f"rep {kept_index}"
            arm = "NO-ATTACK-CONTROL" if control else "attack"
            rec.notes = (f"{rec.notes} [{tag}, arm={arm}, "
                         f"attack_present={'no' if control else 'yes'}, "
                         f"cell_id={rec.cell_id}]")
            records.append(rec)
            print(f"[{vector}] {tag} mit={'ON ' if mitigation else 'OFF'} "
                  f"peak_rss={rec.peak_rss_mb} cpu={rec.mean_cpu_pct} "
                  f"p95={rec.lat_p95_ms} err={rec.error_rate}")
            time.sleep(cooldown_s)
    return records


def run_smoke_main(vector: str, one_run: Callable[[bool], Record]) -> None:
    """Standard CLI for every vector's run_smoke.py.

    ``--reps N`` (default 10, min enforced at 5 with a warning), ``--warmup``,
    ``--cooldown``, ``--seed``. Writes results/real/<vector>.json.
    """
    ap = argparse.ArgumentParser(description=f"real replicated smoke test for {vector}")
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS,
                    help="kept repetitions per mitigation state (default 10)")
    ap.add_argument("--warmup", type=int, default=DEFAULT_WARMUP,
                    help="discarded warm-up reps (default 1)")
    ap.add_argument("--cooldown", type=float, default=DEFAULT_COOLDOWN_S,
                    help="seconds between runs (default 2.0)")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--control", action="store_true",
                    help="run the NO-ATTACK baseline arm (server up, benign "
                         "probe, attack not invoked). Defaults --tag to "
                         "'control'. See paper Sec. 3 success criterion.")
    ap.add_argument("--tag", type=str, default=os.environ.get("SMOKE_TAG", ""),
                    help="output filename suffix, e.g. --tag anchor2 -> "
                         "results/real/<vector>__anchor2.json")
    args = ap.parse_args()

    tag = args.tag or ("control" if args.control else "")
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    fname = f"{vector}__{tag}.json" if tag else f"{vector}.json"
    out_path = os.path.join(root, "results", "real", fname)
    records = run_reps(vector, one_run, reps=args.reps, warmup=args.warmup,
                       cooldown_s=args.cooldown, seed=args.seed,
                       control=args.control)
    write_records(records, out_path)
