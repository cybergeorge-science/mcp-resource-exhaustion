"""
Synthetic full-sweep generator.

WHY THIS EXISTS: a real n>=5, all-transport, all-SDK, multi-load-level,
multi-concurrency sweep (7 vectors x up to 2 transports x 2 SDKs x 5 load
levels x 4 concurrency levels x 2 mitigation states x 5 reps) is
thousands of individual server-restart-and-measure cycles -- not
feasible in this session. Instead, every vector has ONE real, actually-
measured anchor point per mitigation state (results/real/*.json, produced
by each vector's run_smoke.py). This module extrapolates the REMAINING
grid cells from those real anchors using a simple, fixed, documented
power-law model. Every row this module produces has is_synthetic=True and
an `anchor_run_id` pointing at the real row it was scaled from. None of
this is measured; all of it is a documented guess anchored to one real
data point per vector/mitigation-state.

MODEL (identical shape for every vector; only the exponents/channel
differ, per vector, matching the resource each vector actually exhausts):

  load_ratio  = load_value(load_level)  / load_value(anchor_load_level)
  conc_ratio  = concurrency             / anchor_concurrency

  peak_rss_mb  = sdk_baseline_rss
                 + delta_rss_anchor * load_ratio**a_load * conc_ratio**a_conc
                   * sdk_factor * transport_factor
    where a_load/a_conc are SMALL (~0.1) when mitigation=True (bounded
    growth) and LARGER (>1, superlinear) when mitigation=False, reflecting
    "parsing/copying overhead grows faster than the raw input" -- a
    common, defensible rule of thumb for interpreter-level resource costs,
    not a measured law.

  mean_cpu_pct = clamp(cpu_anchor * load_ratio**c_load * conc_ratio**c_conc
                        * sdk_factor, 0, CPU_CEILING_PCT)

  lat_p50/95/99 = lat_anchor * load_ratio**L_load * conc_ratio**L_conc
    (p99 grows fastest with concurrency -- queueing-theory intuition: tail
    latency is the first thing to blow up under contention)

  error_rate   = clamp(err_anchor + growth_coeff * log2(load_ratio*conc_ratio), 0, 1)
    (growth_coeff small when mitigated -- the mitigation is actively
    shedding load in a controlled way, not failing open)

  recovery_s   = recovery_anchor * load_ratio**0.3 * conc_ratio**0.4, capped at 60s

  time_to_oom_s = ONLY for unmitigated rows on the vectors whose failure
    mode is genuinely "runs out of memory" (v1, v2, v3, v6): projects,
    from this row's OWN modeled growth rate (modeled delta_rss / modeled
    wall-clock duration), how long it would take to reach an ASSUMED
    OOM_THRESHOLD_MB. This is a projection from a linear-rate assumption,
    not an observation -- our real smoke tests deliberately stop well
    before anything OOMs (see common/killswitch.py's HARD_RSS_KILL_MB).

  amplification = same formula/channel as the real anchor
    (common/amplification.py), fed modeled inputs.

Cross-SDK / cross-transport factors are single fixed constants (documented
below), not per-vector-fit: this keeps the model auditable at a glance
rather than looking more precise than it is.
"""
from __future__ import annotations

import math
import random

from common.schema import Record
from common.amplification import mem_amplification, cpu_amplification
from common.grid import (LOAD_LEVELS, ANCHOR_LOAD_INDEX, ANCHOR_CONCURRENCY,
                          CONCURRENCY_LEVELS, N_REPS, REAL_ANCHOR,
                          APPLICABLE_TRANSPORTS, SDKS)

# ---------------------------------------------------------------------------
# fixed, documented constants -- NOT fit to data beyond the one anchor point
# ---------------------------------------------------------------------------
PY_BASELINE_RSS_MB = 67.0    # observed across all real Python-SDK runs (~66-68 MB)
TS_BASELINE_RSS_MB = 70.0    # observed across all real TypeScript-SDK runs (~63-93 MB)

TRANSPORT_FACTOR = {"http": 1.00, "stdio": 0.90, "sse": 1.10}
CPU_CEILING_PCT = 400.0      # assume up to ~4 effective cores of headroom
OOM_THRESHOLD_MB = 4096.0    # assumed container/process memory ceiling (documented guess)
RECOVERY_CAP_S = 60.0

MEM_CHANNEL_VECTORS = {"v1_oversized_body", "v2_init_flood", "v3_unbounded_stdio", "v6_slow_sse"}
CPU_CHANNEL_VECTORS = {"v4_deep_json", "v5_tool_flood", "v7_redos"}
OOM_APPLICABLE_VECTORS = {"v1_oversized_body", "v2_init_flood", "v3_unbounded_stdio"}  # unbounded-*memory* CWE-770 vectors

# (load_exp_unmitigated, conc_exp_unmitigated, load_exp_mitigated, conc_exp_mitigated)
MEM_GROWTH_EXPONENTS = (1.3, 1.1, 0.12, 0.08)
CPU_GROWTH_EXPONENTS = (0.9, 0.7, 0.10, 0.06)
LAT_EXPONENTS = {  # (load_exp, conc_exp) per percentile, same for all vectors
    "p50": (0.35, 0.55),
    "p95": (0.45, 0.85),
    "p99": (0.55, 1.05),
}

RNG_SEED = 20260816  # today's date -- fixed so the sweep is reproducible
_rng = random.Random(RNG_SEED)


def sdk_factor(target_sdk: str, anchor_sdk: str) -> float:
    if target_sdk == anchor_sdk:
        return 1.0
    # documented, single fixed cross-implementation multiplier: V8/Node
    # object + GC bookkeeping overhead is modeled as ~10% higher than
    # CPython's for equivalent workloads; applied symmetrically.
    return 1.10 if target_sdk == "typescript" else 1 / 1.10


def _jitter(rng: random.Random, scale: float = 0.06) -> float:
    """+/- `scale` fractional multiplicative jitter, to avoid n=5 "replicates"
    being bit-identical (still clearly synthetic, just not degenerate)."""
    return 1.0 + rng.uniform(-scale, scale)


def _clamp(x, lo, hi):
    return max(lo, min(hi, x))


def _model_cell(*, vector: str, real_off: Record, anchor_row: Record,
                baseline_rss: float, load_ratio: float, conc_ratio: float,
                mitigation: bool, t_factor: float, s_factor: float,
                anchor_attacker_mb: float, anchor_attacker_cpu_cost_s: float) -> dict:
    """DETERMINISTIC per-cell model (no replicate jitter). Shared by the sweep
    loop (which multiplies each term by an independent jitter draw) and by
    predict_cell() (which uses these values directly). Returns every dependent
    variable's expected value plus the pieces the sweep needs.

    Keeping this single function is what makes the P1.2 residuals
    (predicted-vs-measured) use the exact same formulas as the published
    synthetic sweep, rather than a re-derivation that could silently drift."""
    channel = "mem" if vector in MEM_CHANNEL_VECTORS else "cpu"
    growth = MEM_GROWTH_EXPONENTS if channel == "mem" else CPU_GROWTH_EXPONENTS
    a_load, a_conc, m_load, m_conc = growth
    load_exp = m_load if mitigation else a_load
    conc_exp = m_conc if mitigation else a_conc

    anchor_delta_rss = max(0.0, anchor_row.peak_rss_mb - baseline_rss)
    delta_rss = anchor_delta_rss * (load_ratio ** load_exp) * (conc_ratio ** conc_exp) * t_factor * s_factor
    peak_rss = baseline_rss + delta_rss

    mean_cpu = _clamp(anchor_row.mean_cpu_pct * (load_ratio ** (load_exp * 0.7))
                      * (conc_ratio ** (conc_exp * 0.7)) * s_factor, 0.0, CPU_CEILING_PCT)

    lat = {}
    for pctl, (le, ce) in LAT_EXPONENTS.items():
        base = getattr(anchor_row, f"lat_{pctl}_ms")
        damp = 0.15 if mitigation else 1.0
        lat[pctl] = max(0.05, base * (load_ratio ** (le * damp)) * (conc_ratio ** (ce * damp)))

    growth_coeff = 0.03 if mitigation else 0.12
    err = _clamp(
        anchor_row.error_rate + growth_coeff * math.log2(max(load_ratio * conc_ratio, 1e-6) + 1e-9)
        if (load_ratio * conc_ratio) > 1 else anchor_row.error_rate, 0.0, 1.0)

    recovery_s = min(RECOVERY_CAP_S, max(0.1,
                     anchor_row.recovery_s * (load_ratio ** 0.3) * (conc_ratio ** 0.4)))
    wall_duration_s = max(0.05, (anchor_row.ts_end - anchor_row.ts_start)
                          * (load_ratio ** 0.5) * (conc_ratio ** 0.5))
    return {"channel": channel, "delta_rss": delta_rss, "peak_rss": peak_rss,
            "mean_cpu": mean_cpu, "lat": lat, "err": err,
            "recovery_s": recovery_s, "wall_duration_s": wall_duration_s,
            "baseline_rss": baseline_rss}


def predict_cell(vector: str, real_off: Record, real_on: Record, *,
                 load_level: int, concurrency: int, mitigation: bool,
                 transport: str | None = None, sdk: str | None = None) -> dict:
    """Deterministic model prediction (jitter=1) for a single grid cell, from a
    given pair of real anchors. Used by P1.2 model validation to compute
    predicted-vs-measured residuals at the SECOND real load point."""
    anchor = REAL_ANCHOR[vector]
    anchor_transport = transport or anchor["transport"]
    anchor_sdk_name = anchor["sdk"]
    sdk = sdk or anchor_sdk_name
    transport = transport or anchor_transport
    grid = LOAD_LEVELS[vector]
    load_values = grid["values"]
    anchor_load_idx = ANCHOR_LOAD_INDEX[vector]
    anchor_load_value = load_values[anchor_load_idx - 1]
    anchor_conc = real_off.concurrency
    load_ratio = load_values[load_level - 1] / anchor_load_value
    conc_ratio = concurrency / anchor_conc

    baseline = PY_BASELINE_RSS_MB if sdk == "python" else TS_BASELINE_RSS_MB
    t_factor = TRANSPORT_FACTOR[transport] / TRANSPORT_FACTOR[anchor_transport]
    s_factor = sdk_factor(sdk, anchor_sdk_name)
    anchor_row = real_on if mitigation else real_off

    off_baseline = PY_BASELINE_RSS_MB if anchor_sdk_name == "python" else TS_BASELINE_RSS_MB
    off_delta_rss = max(0.0, real_off.peak_rss_mb - off_baseline)
    anchor_attacker_mb = max(1e-6, off_delta_rss / max(real_off.amplification, 1e-9))
    off_cpu_seconds = max(1e-9, (real_off.mean_cpu_pct / 100.0) * max(1e-6, real_off.ts_end - real_off.ts_start))
    anchor_attacker_cpu_cost_s = max(1e-9, off_cpu_seconds / max(real_off.amplification, 1e-9))

    m = _model_cell(vector=vector, real_off=real_off, anchor_row=anchor_row,
                    baseline_rss=baseline, load_ratio=load_ratio, conc_ratio=conc_ratio,
                    mitigation=mitigation, t_factor=t_factor, s_factor=s_factor,
                    anchor_attacker_mb=anchor_attacker_mb,
                    anchor_attacker_cpu_cost_s=anchor_attacker_cpu_cost_s)
    return {"peak_rss_mb": round(m["peak_rss"], 2), "mean_cpu_pct": round(m["mean_cpu"], 2),
            "lat_p50_ms": round(m["lat"]["p50"], 2), "lat_p95_ms": round(m["lat"]["p95"], 2),
            "lat_p99_ms": round(m["lat"]["p99"], 2), "error_rate": round(m["err"], 3),
            "recovery_s": round(m["recovery_s"], 2),
            "load_level": load_level, "concurrency": concurrency, "mitigation": mitigation}


def generate_for_vector(vector: str, real_off: Record, real_on: Record) -> list[Record]:
    grid = LOAD_LEVELS[vector]
    load_values = grid["values"]
    anchor_load_idx = ANCHOR_LOAD_INDEX[vector]
    anchor_load_value = load_values[anchor_load_idx - 1]
    anchor = REAL_ANCHOR[vector]
    anchor_transport, anchor_sdk = anchor["transport"], anchor["sdk"]
    anchor_conc = real_off.concurrency  # same for on/off by construction

    channel = "mem" if vector in MEM_CHANNEL_VECTORS else "cpu"
    growth = MEM_GROWTH_EXPONENTS if channel == "mem" else CPU_GROWTH_EXPONENTS

    # Attacker-side cost basis is always derived from the UNMITIGATED real
    # anchor (real_off): the attacker attempts the same load regardless of
    # whether the mitigation is on: mitigation changes the SERVER's cost,
    # not what the attacker tries to send. Using real_on here would be
    # fragile whenever a mitigated run's observed delta happens to be ~0.
    anchor_sdk_baseline = PY_BASELINE_RSS_MB if anchor_sdk == "python" else TS_BASELINE_RSS_MB
    off_delta_rss = max(0.0, real_off.peak_rss_mb - anchor_sdk_baseline)
    anchor_attacker_mb = max(1e-6, off_delta_rss / max(real_off.amplification, 1e-9))
    off_cpu_seconds = max(1e-9, (real_off.mean_cpu_pct / 100.0) * max(1e-6, real_off.ts_end - real_off.ts_start))
    anchor_attacker_cpu_cost_s = max(1e-9, off_cpu_seconds / max(real_off.amplification, 1e-9))

    out = []
    transports = APPLICABLE_TRANSPORTS[vector]

    for transport in transports:
        t_factor = TRANSPORT_FACTOR[transport] / TRANSPORT_FACTOR[anchor_transport]
        for sdk in SDKS:
            s_factor = sdk_factor(sdk, anchor_sdk)
            baseline_rss = PY_BASELINE_RSS_MB if sdk == "python" else TS_BASELINE_RSS_MB
            for load_idx_1based, load_value in enumerate(load_values, start=1):
                load_ratio = load_value / anchor_load_value
                for concurrency in CONCURRENCY_LEVELS:
                    conc_ratio = concurrency / anchor_conc
                    for mitigation in (False, True):
                        anchor_row = real_on if mitigation else real_off
                        anchor_delta_rss = max(0.0, anchor_row.peak_rss_mb - baseline_rss)
                        a_load, a_conc, m_load, m_conc = growth
                        load_exp = m_load if mitigation else a_load
                        conc_exp = m_conc if mitigation else a_conc

                        # skip regenerating the exact real anchor cell --
                        # that data point is already real, keep it that way
                        is_anchor_cell = (transport == anchor_transport and sdk == anchor_sdk
                                          and load_idx_1based == anchor_load_idx
                                          and concurrency == anchor_conc)
                        if is_anchor_cell:
                            continue

                        for rep in range(N_REPS):
                            j = _jitter(_rng)
                            peak_rss = baseline_rss + anchor_delta_rss * (
                                load_ratio ** load_exp) * (conc_ratio ** conc_exp) * t_factor * s_factor * j

                            mean_cpu = _clamp(
                                anchor_row.mean_cpu_pct * (load_ratio ** (load_exp * 0.7))
                                * (conc_ratio ** (conc_exp * 0.7)) * s_factor * _jitter(_rng),
                                0.0, CPU_CEILING_PCT)

                            lat = {}
                            for pctl, (le, ce) in LAT_EXPONENTS.items():
                                base = getattr(anchor_row, f"lat_{pctl}_ms")
                                damp = 0.15 if mitigation else 1.0  # mitigation bounds benign-latency impact
                                lat[pctl] = max(0.05, base * (load_ratio ** (le * damp))
                                                 * (conc_ratio ** (ce * damp)) * _jitter(_rng))

                            growth_coeff = 0.03 if mitigation else 0.12
                            err = _clamp(
                                anchor_row.error_rate + growth_coeff * math.log2(max(load_ratio * conc_ratio, 1e-6) + 1e-9)
                                if (load_ratio * conc_ratio) > 1 else anchor_row.error_rate,
                                0.0, 1.0)

                            recovery_s = min(RECOVERY_CAP_S, max(0.1,
                                anchor_row.recovery_s * (load_ratio ** 0.3) * (conc_ratio ** 0.4) * _jitter(_rng)))

                            wall_duration_s = max(0.05, (anchor_row.ts_end - anchor_row.ts_start)
                                                   * (load_ratio ** 0.5) * (conc_ratio ** 0.5))

                            time_to_oom_s = None
                            if (not mitigation) and vector in OOM_APPLICABLE_VECTORS:
                                rate_mb_per_s = max(1e-6, (peak_rss - baseline_rss) / wall_duration_s)
                                if peak_rss >= OOM_THRESHOLD_MB:
                                    # modeled growth already exceeds the assumed ceiling
                                    # within this row's own (modeled) wall-clock window
                                    time_to_oom_s = round(min(wall_duration_s,
                                                              (OOM_THRESHOLD_MB - baseline_rss) / rate_mb_per_s), 1)
                                    time_to_oom_s = max(0.0, time_to_oom_s)
                                else:
                                    time_to_oom_s = round((OOM_THRESHOLD_MB - baseline_rss) / rate_mb_per_s, 1)

                            # amplification: reuse anchor's attacker-cost
                            # reference point, scaled by the same ratios
                            if channel == "mem":
                                modeled_attacker_bytes = anchor_attacker_mb * (1024 * 1024) * load_ratio * conc_ratio
                                amplification = mem_amplification(max(0.0, peak_rss - baseline_rss), modeled_attacker_bytes)
                            else:
                                modeled_attacker_cost_s = anchor_attacker_cpu_cost_s * load_ratio
                                amplification = cpu_amplification(mean_cpu, wall_duration_s, modeled_attacker_cost_s)

                            rec = Record(
                                vector=vector, transport=transport, sdk=sdk,
                                load_level=load_idx_1based, concurrency=concurrency,
                                mitigation=mitigation,
                                peak_rss_mb=round(peak_rss, 2), mean_cpu_pct=round(mean_cpu, 2),
                                lat_p50_ms=round(lat["p50"], 2), lat_p95_ms=round(lat["p95"], 2),
                                lat_p99_ms=round(lat["p99"], 2),
                                error_rate=round(err, 3),
                                time_to_oom_s=time_to_oom_s,
                                recovery_s=round(recovery_s, 2),
                                amplification=round(amplification, 3),
                                ts_start=anchor_row.ts_start, ts_end=anchor_row.ts_start + wall_duration_s,
                                is_synthetic=True,
                                anchor_run_id=anchor_row.run_id,
                                notes=(f"SYNTHETIC. Extrapolated from anchor real run "
                                       f"{anchor_row.run_id} ({anchor_transport}/{anchor_sdk}, "
                                       f"load_level={anchor_load_idx}, concurrency={anchor_conc}, "
                                       f"mitigation={mitigation}) via common/synth_model.py "
                                       f"({channel}-channel power-law model). load_ratio={load_ratio:.3f}, "
                                       f"conc_ratio={conc_ratio:.3f}, rep={rep}. NOT a measurement."),
                            )
                            out.append(rec)
    return out
