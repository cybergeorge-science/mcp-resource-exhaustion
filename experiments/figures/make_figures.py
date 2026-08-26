"""
Generates Figures 1-3 of paper_short.md (the paper's own numbering; earlier
drafts of this script called them Figures 2-4) directly from
experiments/results/all_results.json (combined real + synthetic dataset).

The real data is REPLICATED: each vector has >=5 kept reps per
(anchor cell x mitigation), plus a second real load point
(results/real/<vector>__anchor2.json, carried into all_results.json). This
script therefore:
  * Figure 1 -- overlays the mean real anchor (with a 95% CI error bar) AND the
    second real load point on the synthetic dose-response sweep. The synthetic
    curve and the real markers are BOTH drawn at that vector's own anchor
    concurrency (see anchor_concurrency()), never at a fixed concurrency=1:
    v1/v2/v4's real anchors are at concurrency 8, and plotting them against a
    concurrency=1 model curve made the model look mis-calibrated when it is
    not;
  * Figure 2 -- draws a TRUE empirical CDF from the raw per-request benign
    latencies (benign_latencies_ms) aggregated across reps, replacing the old
    3-point (p50/p95/p99) reconstruction;
  * Figure 3 -- amplification per vector using the mean over the real reps.

No numbers are fabricated: every point is read from a real rep row, an
aggregate of real rep rows, or a synthetic row the dataset already carries.
Real vs. synthetic is always encoded redundantly (marker + label), never color
alone. Palette: Okabe-Ito colorblind-safe.
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from common import stats  # noqa: E402
from common.grid import ANCHOR_LOAD_INDEX  # noqa: E402

DATA = os.path.join(HERE, "..", "results", "all_results.json")
OUT = HERE

with open(DATA, "r", encoding="utf-8") as fh:
    rows = json.load(fh)

VECTORS = ["v1_oversized_body", "v2_init_flood", "v3_unbounded_stdio",
           "v4_deep_json", "v5_tool_flood", "v6_slow_sse", "v7_redos"]
VLABEL = {
    "v1_oversized_body": "v1 oversized body", "v2_init_flood": "v2 init/session flood",
    "v3_unbounded_stdio": "v3 unbounded stdio", "v4_deep_json": "v4 deep nested JSON",
    "v5_tool_flood": "v5 tool-invocation flood", "v6_slow_sse": "v6 slow-SSE",
    "v7_redos": "v7 ReDoS",
}
OKABE_ITO = ["#000000", "#E69F00", "#56B4E9", "#009E73", "#F0E442", "#0072B2", "#D55E00"]
VCOLOR = dict(zip(VECTORS, OKABE_ITO))
MEM_VECTORS = ["v1_oversized_body", "v2_init_flood", "v3_unbounded_stdio", "v6_slow_sse"]
CPU_VECTORS = ["v4_deep_json", "v5_tool_flood", "v7_redos"]

by_vec = {v: [] for v in VECTORS}
for r in rows:
    by_vec[r["vector"]].append(r)


def real_kept(v):
    return [r for r in by_vec[v] if not r["is_synthetic"]
            and (r.get("rep_index") is None or r["rep_index"] >= 0)]


def anchor_concurrency(v):
    """The concurrency level the vector's REAL anchor was actually measured at.

    Derived from the data rather than hard-coded: the real anchor reps for
    v1/v2/v4 ran at concurrency 8 and for v3/v5/v6/v7 at concurrency 1. Every
    real marker and every synthetic curve in Figure 1 is drawn at this value,
    so the modeled line and the measured points share an axis.
    """
    a_idx = ANCHOR_LOAD_INDEX[v]
    cs = {r["concurrency"] for r in real_kept(v) if r["load_level"] == a_idx}
    if len(cs) != 1:
        raise SystemExit(f"{v}: expected exactly one anchor concurrency, got {sorted(cs)}")
    return cs.pop()


def cell_reps(v, mitigation, load_level):
    """Real reps for a cell, pinned to the vector's anchor concurrency."""
    c = anchor_concurrency(v)
    return [r for r in real_kept(v)
            if bool(r["mitigation"]) is mitigation and r["load_level"] == load_level
            and r["concurrency"] == c]


def mean_field(rws, field):
    vals = [r[field] for r in rws if r.get(field) is not None]
    return sum(vals) / len(vals) if vals else None


# ---------------------------------------------------------------------------
# Figure 1 (paper numbering): dose-response with mean real anchor (95% CI)
# + 2nd real point, at each vector's own anchor concurrency.
# ---------------------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(11, 4.8))


def dose_panel(ax, vector_list, metric, ylabel, title):
    for v in vector_list:
        # the modeled curve must sit at the SAME concurrency as this vector's
        # real markers, otherwise the two are not comparable (see docstring)
        conc = anchor_concurrency(v)
        pts = [r for r in by_vec[v]
               if r["is_synthetic"] and r["concurrency"] == conc and not r["mitigation"]]
        agg = {}
        for r in pts:
            agg.setdefault(r["load_level"], []).append(r[metric])
        xs = sorted(agg)
        ys = [sum(agg[x]) / len(agg[x]) for x in xs]
        ax.plot(xs, ys, marker="o", ms=4, lw=1.8, color=VCOLOR[v],
                label=f"{VLABEL[v]} (synthetic sweep, C={conc})")
        # real anchor (mean over reps) + 95% CI error bar
        a_idx = ANCHOR_LOAD_INDEX[v]
        anchor_reps = cell_reps(v, False, a_idx)
        if anchor_reps:
            ci = stats.mean_sd_ci([r[metric] for r in anchor_reps if r.get(metric) is not None])
            ax.errorbar([a_idx], [ci["mean"]], yerr=[[ci["half_width"]], [ci["half_width"]]],
                        fmt="*", ms=15, color=VCOLOR[v], mec="black", mew=0.7,
                        ecolor="black", elinewidth=0.9, capsize=3, zorder=6)
        # second real load point, plotted as a diamond
        second_reps = cell_reps(v, False, a_idx + 1)
        if second_reps:
            m2 = mean_field(second_reps, metric)
            ax.scatter([a_idx + 1], [m2], marker="D", s=42, color=VCOLOR[v],
                       edgecolor="black", linewidth=0.7, zorder=6)
    ax.set_xlabel("load level (1-5)")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=10)
    ax.set_yscale("log")
    ax.grid(True, which="both", axis="y", alpha=0.25, linewidth=0.5)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)


def _conc_note(vector_list):
    return ", ".join(f"{v.split('_')[0]}: C={anchor_concurrency(v)}" for v in vector_list)


dose_panel(axes[0], MEM_VECTORS, "peak_rss_mb", "peak RSS (MB, log scale)",
           "(a) Memory-channel vectors, unmitigated,\nat each vector's own anchor "
           f"concurrency ({_conc_note(MEM_VECTORS)})")
dose_panel(axes[1], CPU_VECTORS, "mean_cpu_pct", "mean CPU % (log scale)",
           "(b) CPU-channel vectors, unmitigated,\nat each vector's own anchor "
           f"concurrency ({_conc_note(CPU_VECTORS)})")

handles0, labels0 = axes[0].get_legend_handles_labels()
handles1, labels1 = axes[1].get_legend_handles_labels()
star_proxy = plt.Line2D([0], [0], marker="*", color="w", markerfacecolor="grey",
                        markeredgecolor="black", markersize=15, linestyle="None",
                        label="real anchor: mean of reps +/- 95% CI (OFF)")
diam_proxy = plt.Line2D([0], [0], marker="D", color="w", markerfacecolor="grey",
                        markeredgecolor="black", markersize=8, linestyle="None",
                        label="second real load point (mean of reps)")
fig.legend(handles0 + handles1 + [star_proxy, diam_proxy],
           labels0 + labels1 + [star_proxy.get_label(), diam_proxy.get_label()],
           loc="lower center", ncol=3, fontsize=7.2, frameon=False, bbox_to_anchor=(0.5, -0.19))
fig.suptitle("Dose-response: resource cost vs. load level, each vector at its own anchor concurrency\n"
             "Lines = synthetic sweep (is_synthetic=true); stars = real anchor (mean of n=10 reps, 95% CI); "
             "diamonds = second real load point (n=10)",
             fontsize=9.3)
fig.tight_layout(rect=[0, 0.12, 1, 0.90])
fig.savefig(os.path.join(OUT, "fig1_dose_response.png"), dpi=300, bbox_inches="tight")
plt.close(fig)

# ---------------------------------------------------------------------------
# Figure 2 (paper numbering): TRUE empirical CDF of raw per-request benign latencies, aggregated
# across reps, for the real anchor cell -- attack (unmitigated) vs mitigated.
# ---------------------------------------------------------------------------
fig, axes = plt.subplots(3, 3, figsize=(11, 9.5))
axes_flat = axes.flat
COND_COLOR = {"attack (unmitigated)": "#D55E00", "mitigated": "#009E73"}


def agg_latencies(v, mitigation):
    a_idx = ANCHOR_LOAD_INDEX[v]
    out = []
    for r in cell_reps(v, mitigation, a_idx):
        lat = r.get("benign_latencies_ms")
        if lat:
            out.extend(lat)
    return sorted(out)


def ecdf(ax, samples, color, label, ls="-"):
    if not samples:
        return
    n = len(samples)
    ys = [(i + 1) / n for i in range(n)]
    xs = list(samples)
    # step from 0; linestyle encodes condition redundantly with color
    ax.step([0] + xs, [0] + ys, where="post", color=color, lw=2, linestyle=ls,
            label=f"{label} (n={n})")


# redundant encoding: color AND linestyle (colorblind-safe, print-safe)
COND_LS = {"attack (unmitigated)": "-", "mitigated": "--"}
for idx, v in enumerate(VECTORS):
    ax = axes_flat[idx]
    for label, mit in (("attack (unmitigated)", False), ("mitigated", True)):
        ecdf(ax, agg_latencies(v, mit), COND_COLOR[label], label, ls=COND_LS[label])
    ax.set_xscale("symlog", linthresh=1)
    ax.set_title(VLABEL[v], fontsize=9)
    ax.set_xlabel("benign request latency (ms)", fontsize=7.5)
    ax.set_ylabel("P(X <= x)", fontsize=7.5)
    ax.tick_params(labelsize=7)
    ax.set_ylim(0, 1.02)
    ax.legend(fontsize=6.5, frameon=False, loc="lower right")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

axes_flat[7].axis("off")
axes_flat[8].axis("off")
fig.suptitle(
    "Empirical CDF of raw per-request benign latency (real anchor cell)\n"
    "TRUE empirical CDF over raw benign_latencies_ms aggregated across reps (is_synthetic=false); "
    "attack vs mitigated, both directly measured.",
    fontsize=9.0)
fig.tight_layout(rect=[0, 0.04, 1, 0.90])
fig.savefig(os.path.join(OUT, "fig2_latency_cdf.png"), dpi=300, bbox_inches="tight")
plt.close(fig)

# ---------------------------------------------------------------------------
# Figure 3 (paper numbering): amplification per vector, real anchors (mean of reps), OFF vs ON.
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(9.5, 5))
x = list(range(len(VECTORS)))
width = 0.35
FLOOR = 0.005
off_vals, on_vals, off_true, on_true = [], [], [], []
for v in VECTORS:
    a_idx = ANCHOR_LOAD_INDEX[v]
    ov = mean_field(cell_reps(v, False, a_idx), "amplification")
    nv = mean_field(cell_reps(v, True, a_idx), "amplification")
    off_true.append(ov)
    on_true.append(nv)
    off_vals.append(ov if ov and ov > 0 else FLOOR)
    on_vals.append(nv if nv and nv > 0 else FLOOR)

ax.bar([i - width/2 for i in x], off_vals, width, color="#D55E00",
       label="mitigation OFF (real, mean of reps)")
ax.bar([i + width/2 for i in x], on_vals, width, color="#009E73",
       label="mitigation ON (real, mean of reps)")
ax.set_yscale("log")
ax.set_xticks(x)
ax.set_xticklabels([VLABEL[v].replace(" ", "\n", 1) for v in VECTORS], fontsize=8)
ax.set_ylabel("amplification (target cost / attacker cost, log scale)")
ax.yaxis.set_major_formatter(mticker.LogFormatterSciNotation())
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.grid(True, which="major", axis="y", alpha=0.25, linewidth=0.5)
for i, v in enumerate(VECTORS):
    if off_true[i] is not None:
        ax.text(i - width/2, off_vals[i] * 1.25,
                f"{off_true[i]:,.2f}" if off_true[i] < 1000 else f"{off_true[i]:,.0f}",
                ha="center", va="bottom", fontsize=6.5, rotation=90)
    if on_true[i] is not None:
        txt = f"{on_true[i]:,.3f}" if on_true[i] < 1000 else f"{on_true[i]:,.0f}"
        ax.text(i + width/2, on_vals[i] * 1.25, txt, ha="center", va="bottom",
                fontsize=6.5, rotation=90)
ax.legend(loc="upper left", fontsize=8, frameon=False)
ax.set_title("Amplification factor per vector, real anchors (mean of reps, OFF vs ON)",
             fontsize=9.3)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "fig3_amplification.png"), dpi=300, bbox_inches="tight")
plt.close(fig)

print("wrote fig1_dose_response.png, fig2_latency_cdf.png, fig3_amplification.png")
