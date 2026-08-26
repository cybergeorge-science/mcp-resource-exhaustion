# Resource Exhaustion as a First-Class MCP Security Property: A Threat Model, Measurement Harness, and Empirical Evaluation

*Claims below are tagged REAL (measured). A labeled synthetic grid exists in the artifact but is not used as evidence.*

---

## Abstract

The Model Context Protocol (MCP) standardizes how LLM applications invoke external tools. Existing MCP security research concentrates on confidentiality and integrity and does not measure whether a protocol-conformant client can exhaust memory, CPU, or sessions so that *other* agents stop being served. We close that gap as an applied measurement study. We map seven resource-exhaustion vectors to CWE-770/400/1333 across the official Python and TypeScript SDKs; ship a reproducible experiment package with a locked result schema; and report replicated measurements (n = 10 per anchor, mean ± 95% CI, Mann–Whitney U, rank-biserial effect sizes, Holm-corrected). At the original short-burst anchors, only unbounded stdio (v3, local `AV:L`) meets a pre-declared concurrent-client availability criterion. A practical follow-up — 32 concurrent workers, 10 s sustained flood, benign echo *during* the attack (n = 8) — shows that the two network-reachable floods do meet it: initialize/session flood (v2) raises established-client p95 8.96 → 49.28 ms (5.50×, p = 0.0009) and tool-invocation flood (v5) 6.56 → 64.14 ms (9.77×, p = 0.0136), with peak RSS 53 → 177 MB and 71 → 246 MB. Four mitigations (v1, v2, v3, v6) reduce their pre-specified resource channel; v7's ~382× gain is attacker-cost, not availability; v4 never reproduced as pathological; v5's pre-specified CPU test fails. Leaving size, session and invocation caps off is not a neutral default.

**Keywords:** Model Context Protocol; denial of service; resource exhaustion; availability; LLM agents; security benchmarking; CWE-770; CWE-400; CWE-1333.

---

## 1. Introduction

MCP hosts, clients, and servers allocate memory for attacker-controlled input, run regular expressions over attacker-controlled strings, and hold connections open as long as a peer trickles bytes. The protocol's own choices — a JSON-RPC layer with no size ceiling [3], no mandated idle timeout, an SSE transport with no mandated backpressure [2] — do nothing to change that, and an MCP server typically sits one hop from an autonomous agent inside a host whose failure mode is not one slow request but an assistant that stops responding.

The most systematic prior effort, MCPSecBench [1], catalogues seventeen attack types across four surfaces, every one a confidentiality or integrity concern. Three more recent MCP papers [10]–[12] *name* availability, and the Ruby SDK has exact-mechanism advisories for oversized bodies, unreaped sessions and unbounded stdio reads [13]–[15], but none of those works reports a replicated resource-cost number or a concurrent-client availability test on the official Python/TypeScript SDKs. That is the gap this paper closes.

This is an **applied measurement study**, not a new-technique paper: the seven weaknesses are decades-old CWE-770/400/1333 classes MCP inherits from any RPC-style protocol, and the mitigations are idiomatic. The contributions are (i) a CWE-mapped, CVE-scoped taxonomy of those classes on the MCP session lifecycle (§3); (ii) a reproducible experiment package with a locked JSON schema (§4); (iii) replicated resource-cost and mitigation numbers plus a practical high-concurrency flood with a concurrent benign client (§5).

**RQ1.** Which of the seven vectors impose measurable resource cost on the official SDKs at a locked anchor? **RQ2.** Which of them move a concurrent well-behaved client against an attack-absent control (Table 3b at the short-burst anchors; Table 3c at a 32-worker, 10 s flood)? **RQ3.** Do idiomatic mitigations reduce the *pre-specified* resource channel without collateral benign rejection?

We are precise about what the results license. All seven are *candidates* for resource exhaustion; v4 never reproduced as pathological. At the original short-burst anchors, availability denial is demonstrated for **v3 only** (local stdin, `AV:L`, Table 3b). Under a practical concurrent-probe flood, **v2 and v5 also meet the same criterion** (Table 3c). v1 and v6 remain resource-cost findings at the loads tested.

---

## 2. Background and Related Work

**MCP architecture.** A *host* instantiates one *client* per connected *server*, each pair holding a stateful session whose lifecycle is initialization, operation, shutdown [2]. A *data layer* carries JSON-RPC 2.0 [3] over tools, resources and prompts; a *transport layer* moves those messages over local *stdio* or *Streamable HTTP* (JSON body or Server-Sent-Events stream) [2]. Each vector in Table 2 attacks a point in that lifecycle — session establishment, framing, parsing, transport timing — not semantic content.

**The availability gap.** Table 1 places this paper against the nearest MCP security work. MCPSecBench [1], a December-2025 SoK [10], a STRIDE/DREAD catalog [11] and VIPER-MCP [12] discuss DoS as a category; none measures RSS/CPU or a concurrent benign client on the official Python/TypeScript SDKs. Practitioner write-ups and sibling-SDK advisories [13]–[16] already describe oversized payloads and unreaped sessions; they are not a substitute for a locked, replicated measurement.

**Table 1 — Closest MCP security work vs. this measurement.**

| Work | CWE-mapped? | Resource cost measured? | Concurrent-client test? | Official Py/TS SDKs? |
|---|---|---|---|---|
| MCPSecBench [1], [19] | no | no (prompt-level ASR) | no | hosts, not SDKs |
| MCP SoK [10] | names DoS | no | no | survey |
| Huang et al. [11] | STRIDE | no | no | threat model |
| VIPER-MCP [12] | taint/CWE mix | no | no | server corpus |
| Ruby SDK CVEs [13]–[15] | 770/400 | advisory | n/a | Ruby only |
| This work | 770/400/1333 | RSS, CPU, p95, error | yes (Tables 3b, 3c) | yes (`mcp` 1.27.0, TS 1.30.0) |

**Resource-exhaustion literature.** These are long-studied RPC failure modes [20]–[22]. CWE-770 [4] is allocation proportional to one attacker-controlled request with no bound checked first (v1, v3, v4 — JSON analogue of XML bombs [26]–[29]). CWE-400 [5] is cumulative or held-connection exhaustion (v2, v5, v6; Slowloris lineage [6]). CWE-1333 [7] is algorithmic complexity [8], [9], [25] (v7).

---

## 3. Threat Model and Taxonomy

**Attacker model.** The attacker acts as an ordinary, protocol-conformant MCP client or peer: for Streamable HTTP and SSE, an unauthenticated network peer able to open TCP connections to the bound address; for stdio, a peer already able to write to the server subprocess's standard input. It needs no credentials beyond the transport's, no special privilege, and no memory-safety bug: every vector uses protocol-legal or near-legal JSON-RPC traffic in an adversarial *shape* (size, nesting depth, rate, timing) rather than adversarial *content*. Unlike MCPSecBench's attacker [1], its goal is not to make the target *do* or *reveal* the wrong thing but to stop it serving anyone else in time.

**Victim model and success criterion.** The smoke tests attack the server side, most exposed to untrusted peers, though the CWEs apply symmetrically to a client parsing attacker-controlled output. We do not require a crash: consistent with CWE-400/770/1333's framing and the standard degradation-versus-denial distinction [20], a vector succeeds whenever a *concurrent, well-behaved* client's latency or error rate moves adversely during the attack, whether or not the server survives.

**What this study measures against that criterion.** We measured an **attack-absent control cell** per vector, **paired within one session** with a fresh unmitigated-attack arm (Table 3b) at the original short-burst anchors. Against that baseline the criterion is met for **v3 only**. A second, pre-declared practical experiment (Table 3c) re-tests v2 and v5 with a benign client that runs *during* a 10 s, 32-worker flood. §5.1's OFF-vs-ON comparisons measure *mitigation efficacy*, not availability.

### Table 2 — Vectors, verified CWEs, and CVE status (official Python/TS SDKs)

CVE search was restricted, per locked scope, to the official Python and TypeScript SDKs; every advisory cited was confirmed by direct fetch. CVSS v3.1 scores are the authors' assessment (availability-only, `C:N/I:N`) except row 7 (published CVE).

| # | Vector | Transport | CWE | CVSS | CVE (Py/TS SDK) |
|---|---|---|---|---|---|
| 1 | Oversized message body | HTTP/stdio | CWE-770 | 5.3 | None (Ruby analogue CVE-2026-67432 [13], out of scope) |
| 2 | Initialize/session flood | HTTP | CWE-400 | 5.3 | None (Ruby CVE-2026-67430 [14], out of scope) |
| 3 | Unbounded stdio stream | stdio | CWE-770 | 4.0 | None (Ruby CVE-2026-63119 [15], out of scope) |
| 4 | Deeply nested JSON | HTTP/stdio | CWE-770 | 4.3 | None (not pathological at the measured load; §5.1 ◊) |
| 5 | Tool-invocation flooding | HTTP | CWE-400 | 4.3 | None |
| 6 | Slow-SSE / slow read | SSE | CWE-400 | 5.3 | None |
| 7 | ReDoS in input validation | HTTP/stdio | CWE-1333 | 7.5 | **Confirmed: CVE-2026-0621 / GHSA-cqwc-fm46-7fff [16]** (TS SDK `UriTemplate.partToRegExp()`; ≥1.3.0,<1.25.2; fixed 1.25.2) |

Row 7's higher score reflects that catastrophic backtracking pins CPU and hangs the server for *all* clients (`A:H`), whereas the other six are scored as degradation (`A:L`) — assessments of the weakness class, not measurements of benign-client impact. Row 3 is `AV:L` because the stdio vector needs a peer already able to write to the server's stdin. The 770/400 split (single-oversized-input allocation vs. cumulative or held-connection exhaustion) refines MITRE's `ChildOf` relation. Five vectors have no matching published CVE in the locked-scope SDKs; we report that plainly rather than manufacture a match, and it is not evidence of absence — the Ruby SDK has an exact-mechanism CVE for three [13]-[15]. Two high-severity Python-SDK availability CVEs [17], [18] were left off rather than force-fit, matching none of the seven mechanisms.

---

## 4. Methodology and Harness

**Environment.** Primary anchors (Tables 3, 3b) ran on one Windows 11 Enterprise 10.0.26100 host, **no cgroups**, `psutil` RSS/CPU every 0.1–0.2 s (a process-level approximation of cgroup `memory.peak`/`cpu.stat`; CPU% can exceed 100% multi-core). SDKs: Python 3.14.3, `mcp` 1.27.0; Node v24.14.0, `@modelcontextprotocol/sdk` 1.30.0; all binds `127.0.0.1`. Every anchor was re-run in a Linux cgroup-v2 container (§5.4). The practical flood (Table 3c) ran on a second Windows host (13th Gen Intel Core i7-13620H, 16 GB RAM, Python 3.12, same pinned SDKs).

**Locked definitions.** Each run records `peak_rss_mb`, `mean_cpu_pct`, `lat_p50/p95/p99_ms` and `error_rate` of a **well-formed benign client**, plus `time_to_oom_s`, `recovery_s` and `amplification`. **Two probe regimes must not be conflated.** At the original anchors the attack subprocess *returns* and the benign probe then runs — so Table 3b measures leftover cost (unreaped sessions, unreleased buffers), not in-flight contention. Table 3c's practical experiment starts the benign client *before* a 10 s flood and keeps issuing `tools/call echo` every 250 ms *during* it; that is the Sec. 3 criterion as written. **Recovery**, locked before any run, is RSS-based: RSS within 110% of the pre-attack baseline for two consecutive 0.2 s samples, polled to an 8 s cap; unconfirmed rows report the cap with `recovery_confirmed=False`. **Amplification** = `target_resource_cost / attacker_cost` on a memory channel for v1, v2, v3, v6 and a CPU channel for v4, v5, v7.

**Real vs. synthetic policy.** Every numbered claim in this paper is a real measurement (`is_synthetic:false`). Anchors use ≥10 kept reps per mitigation state, a fresh server process, randomized OFF/ON order, one discarded warm-up, plus a second real load point (n = 10, unadjusted). A labeled power-law grid exists in the artifact for illustration; **we make no empirical claim from it**, and we do not plot it as a result. Concurrency 32 for v2/v5 is measured in Table 3c, not modeled.

**Statistics.** We report mean ± 95% t-interval (n<30) for roughly-symmetric DVs and median [IQR] for skewed benign p95 [34]–[36], with two-sided Mann–Whitney U and rank-biserial/Cliff's δ [37]. At n=10, U=0 yields a tie-corrected normal-approximation p = 0.0002 (SciPy exact ≈1.1×10⁻⁵); **0.0002 is the module's approximate value, not a floor**. The module is cross-validated against SciPy's *asymptotic* method. The pre-specified mitigation family is one primary-channel OFF-vs-ON test per vector (m = 7), Holm–Bonferroni (§6.1). Table 3c is a separate two-test family (v2, v5 concurrent p95). The experiment package is the vector drivers, locked schema, sampler and analyzers; it is not a drop-in plugin for third-party servers.

**Practical flood protocol (Table 3c, pre-declared).** For v2 and v5 only: concurrency 32, wall-clock 10 s, attack in a child process, benign client in the parent, control vs attack order randomized within each rep, n = 8 kept + 1 warm-up. Success criterion identical to Table 3b. Primary DV: established-session echo p95 and error rate. Secondary: fresh-`initialize` error rate, peak RSS, CPU.

---

## 5. Results

### 5.1 Mitigation OFF vs. ON at the real anchors

**Table 3 — Mitigation OFF vs. ON at each vector's real anchor cell (REAL, n = 10 reps per mitigation state; mean ± 95% CI, median [IQR] for benign p95 latency; two-sided Mann–Whitney U).** *Columns:* Mit (OFF/ON); Peak RSS and RSS Δ (peak minus that rep's pre-attack baseline), MB; CPU % (mean, can exceed 100% multi-core); Benign p95 (concurrent benign client, ms); Err (benign error rate); Recov (s); MWU p/r (OFF-vs-ON Mann–Whitney U p on the RSS and CPU per-rep distributions, with rank-biserial *r*; negative = ON lower, |r| = 1.00 = complete separation). The recurring `p = 0.0002` is §4's tie-corrected **normal-approximation** value, **not a floor** (SciPy exact ≈1.1×10⁻⁵). Parenthetical % on an ON row = reduction vs. its OFF row. *(CPU ch.)* marks the vectors (v4, v5, v7) whose channel is CPU, not RSS growth — but for §6.1's family v5 is scored on peak RSS, a post-hoc reassignment declared in note ∗. **Bold** = p < 0.05 *uncorrected*.

| Vector | Mit | Peak RSS | RSS Δ | CPU % | Benign p95 med[IQR] | Err | Recov | MWU p (r) RSS/CPU |
|---|---|---|---|---|---|---|---|---|
| v1 oversized body | OFF | 291.56±21.04 | 223.85±21.04 | 6.39±0.50 | 7.42 [7.03, 12.73] | 0.00 | 8.00±0.00 | **0.0002** (r −1.00) / **0.037** (r −0.56) |
| | ON | 70.60±0.55 | 3.03±0.60 (−98.6%) | 5.59 [5.42, 5.76] ‡ | 7.09 [6.70, 22.09] | 0.00 | 0.20±0.00 | — |
| v2 init/session flood | OFF | 77.56±0.15 | 9.91±0.18 | 19.72±18.09 | 6.33 [5.98, 11.68] | 0.00 | 8.00±0.00 | **0.0002** (r −1.00) / **0.004** (r −0.78) |
| | ON | 68.87±0.18 | 1.42±0.17 (−85.6%) | 5.53±1.17 | 2.46 [2.07, 11.63] | **1.00** | 0.20±0.00 | — |
| v3 unbounded stdio | OFF | 260.53±18.99 | 198.13±18.92 | 13.79±1.12 | 2410.76 [2409.94, 2411.47] | 0.20 | 5.41±0.00 | **0.0002** (r −1.00) / **0.0001** (r −1.00) |
| | ON | 62.48±0.21 | 0.07±0.06 (−100%) | 0.00 [0.00, 0.00] ‡ | 0.00 [0.00, 0.00] † | **1.00** † | 0.20±0.00 | — |
| v4 deep nested JSON | OFF | 70.09±0.16 | (CPU ch.) | 2.97±0.37 ◊ | 8.03 [6.83, 16.76] | 0.00 | 0.20±0.00 | **0.0002** (r −1.00) / **0.037** (r −0.56) |
| | ON | 69.03±0.12 | (CPU ch.) | 2.46±0.33 (−17.1%) ◊ | 9.99 [6.65, 19.33] | 0.00 | 0.20±0.00 | — |
| v5 tool-invoke flood | OFF | 96.48±3.13 | (CPU ch.) | 4.25±0.56 | 4.21 [3.66, 10.53] | 0.00 | 7.78±0.06 | **0.0002** (r −1.00) / 0.186 (r +0.36) |
| | ON | 78.13±2.87 | (CPU ch.) | 5.62±1.60 ∗ | 4.68 [2.82, 14.83] | **0.83** | 0.20 [0.20, 4.56] ‡ | — |
| v6 slow-SSE | OFF | 101.79±2.98 | 29.62±2.94 | 0.88±0.39 | 22.45 [19.78, 25.25] | 0.00 | 7.68±0.72 | **0.0002** (r −1.00) / 0.053 (r +0.52) |
| | ON | 74.73±2.39 | 2.65±2.39 (−91.0%) | 2.05±1.11 | 19.62 [17.75, 20.96] | 0.00 | 0.20 [0.20, 0.20] ‡ | — |
| v7 ReDoS | OFF | 67.13±0.21 | (CPU ch.) | 62.28±1.31 | 3.76 [3.27, 4.42] | 0.00 | 0.20±0.00 | 0.677 (r +0.12) / **0.0001** (r −1.00) |
| | ON | 67.13±0.24 | (CPU ch.) | 1.00±0.25 (−98.4%) | 2.17 [2.08, 2.29] | 0.00 | 0.20±0.00 | — |

† v3-ON's `0.00` latency and `1.00` error rate reflect that the mitigated connection closed after only 2 MB of the 20 MB payload was accepted, so no benign round trip completed; recovery is 0.20 s because RSS never grew. ‡ Four ON-cells have a per-rep spread wider than their mean, so a symmetric t-interval would fall below zero on a non-negative quantity; for these we report median [IQR] (v1-ON CPU carries one flagged, not dropped, 147.4% outlier; v3-ON CPU is 0.0% in eight of ten reps; v5-ON and v6-ON recovery are bimodal). ◊ An earlier single v4 run measured 145.66% unmitigated CPU, which did **not** reproduce across 10 reps: the unmitigated server accepts the depth-1000 payload cheaply (2.97% CPU, HTTP 200) and the depth-64 cap rejects it (HTTP 400) at indistinguishable CPU, so **v4's unmitigated cost never reproduced as pathological**; the mitigation's value is early rejection. ∗ v5's CPU *rises* under mitigation as a metric artifact (rejected requests return almost instantly, so the window fills with cheap rejections); the unambiguous evidence is the peak-RSS drop (96.48→78.13 MB, `p = 0.0002`) and admitted requests (400/400 vs. 20/400). **We declare this a post-hoc change of endpoint:** v5's pre-specified channel was CPU, where the test **fails (`p = 0.186`)**; it is flagged `primary_channel_post_hoc: true`.

**The ReDoS headline is an attacker-cost figure, not the benign p95 in the table.** The 382× number is the *attacker's own* pathological-request latency, recorded per rep only in the free-text `notes` field of each v7 record (as the `latency_ms` entry of an embedded `attack_result={...}` string — **there is no top-level `attack_result.latency_ms` schema field**), re-derived over the 10 unmitigated and 10 mitigated reps: **mean 2181.6 ms → 5.72 ms (ratio 381.7 ≈ 382×)**, mean CPU falling 62.28% ± 1.31 → 1.00% ± 0.25 (`p = 0.0001`, r −1.00). This is an *attacker-cost* reduction, **not** a benign-availability gain: the benign p95 barely moves (3.76 → 2.17 ms) and against the measured baseline (Table 3b) v7 shows no adverse move. **Naive global rate limiting collaterally rejects benign traffic:** v2 and v5's limits use one global counter (no client identity to key on without auth), so the benign probe's own requests sometimes landed in the exhausted window — benign error rate 1.00 (v2-ON) and 0.83 (v5-ON) across all reps, the server protected at the direct cost of legitimate users sharing its window.

![Figure 1. Empirical CDF of benign-request latency at each real anchor cell (REAL, both conditions `is_synthetic:false`), pooling per-request latencies over all 10 reps, unmitigated vs. mitigated. The mitigated curve sits at or left of the unmitigated one for the memory-channel vectors; v3-mitigated is degenerate all-zero because the connection closes before any benign round trip completes.](experiments/figures/fig2_latency_cdf.png)

**Table 3b — No-attack benign baseline vs. attack-present (unmitigated) benign client, measured back-to-back within one session at each vector's real anchor (REAL, n = 10 reps per arm; benign p95 in ms, median [IQR]; MWU p = two-sided Mann–Whitney U of the two per-rep benign-p95 distributions; controls marked `attack_present=no`).** "Yes" requires an *adverse* move: ≥2× median latency rise at p < 0.05, or a benign error-rate rise ≥ 0.10.

| Vector | No-attack p95 med[IQR] | No-attack err | Attack-OFF p95 med[IQR] | Attack-OFF err | MWU p (ctrl vs OFF) | §3 criterion met? |
|---|---|---|---|---|---|---|
| v1 oversized body | 12.35 [5.92, 17.73] | 0.00 | 10.12 [6.19, 14.71] | 0.00 | 0.7913 | no |
| v2 init/session flood | 10.33 [5.03, 17.75] | 0.00 | 16.21 [12.56, 21.30] | 0.00 | 0.3447 | no |
| v3 unbounded stdio | 3.60 [2.23, 4.35] | 0.00 | 2409.14 [2403.94, 2412.42] | 0.20 | **0.0002** | **yes** |
| v4 deep nested JSON | 10.70 [6.51, 20.85] | 0.00 | 7.54 [7.21, 17.04] | 0.00 | 0.9698 | no |
| v5 tool-invocation flood | 17.07 [14.34, 21.12] | 0.00 | 5.90 [5.00, 13.74] | 0.00 | 0.0113 ∘ | no |
| v6 slow-SSE | 25.88 [17.68, 26.31] | 0.00 | 16.54 [13.05, 18.21] | 0.00 | 0.0493 ∘ | no |
| v7 ReDoS | 5.63 [5.04, 6.21] | 0.00 | 4.20 [3.82, 5.00] | 0.00 | 0.0058 ∘ | no |

∘ v5, v6 and v7 show a *statistically* significant p in the **non-adverse direction** — attack-present benign p95 is *lower* than the no-attack baseline (5.90 vs. 17.07; 16.54 vs. 25.88; 4.20 vs. 5.63 ms) — so the criterion is not met. The likeliest mechanism is a warm-up effect (the original probe runs *after* the burst; JIT/connection pools are hot). Only **v3** is adverse at this regime (3.60 → 2409.14 ms, ~670×, error 0.00 → 0.20). **Caveat:** v3 is a single serialized stdio pipe, so a ~20 MB unterminated line can stall the benign client by head-of-line blocking independent of CWE-770 allocation. RSS does climb to ~260 MB; the mitigation removes both mechanisms at once. Table 3b is therefore *not* evidence that network floods cannot DoS a concurrent agent — that is Table 3c.

### 5.2 Second real load point (not a model)

A second measured load point per vector (n = 10, unadjusted) is in the artifact. Mitigated peak RSS stays bounded. Unmitigated CPU and latency tails do not interpolate cleanly — at v7's 30-character input, benign p95 is 3013 ms with error rate 1.00 and still lacks a matched control. We do not treat any synthetic residual as a result.

### 5.3 Recovery and amplification

Unmitigated v1 and v2 recovery pins at the 8 s cap (`recovery_confirmed=False`, so *at least* 8 s), dropping to 0.20 s mitigated; v5-ON and v6-ON recovery are **bimodal** (v5-ON median 0.20 s [IQR 0.20, 4.56]), so we report medians. Amplification (Figure 2) shows the mitigations do not all behave alike.

![Figure 2. Amplification factor per vector at the real anchors (REAL rows only, mean over 10 reps), mitigation OFF vs. ON, log y-axis. Only v1 (2.80→0.038), v3 (9.91→0.034) and v7 (526,823→60.1) collapse to the floor; v2 (295→42) and v6 (155,302→13,930) fall substantially but stay well above it; v4 drops only ~18% (18,262→14,919). v5's mitigated bar is higher (14.79→26.72) purely as the CPU-channel artifact of Section 5.1.](experiments/figures/fig3_amplification.png)

### 5.4 Linux/cgroup-v2 confirmation

Re-running every anchor under kernel `memory.peak`/`cpu.stat` accounting in a cgroup-v2 container, the mitigation direction and separation reproduce for all four memory-channel vectors (v1 600.0→230.5, v3 331.9→46.5 MB and likewise v2, v6), so the central claim is not a psutil artifact. That re-run also gave this paper's first real measured OOM endpoint: a tightly-capped run against the Node/TypeScript stdio server ended in a kernel SIGKILL in 3/3 attempts, mean 0.093 s, whereas the Python server only throttled at the cap. Container-granularity accounting inflates the cgroup CPU column, so psutil stays primary.

### 5.5 External validity: a third-party server we did not write

The identical *anchor* attacks (same loads, loopback, n = 8 reps per arm) ran against **`@modelcontextprotocol/server-everything`** (pinned 2026.8.18), the official project's reference server, on SDK 1.30.0. **Four of the seven weakness classes reproduce as resource cost** (v1, v2, v3, v5). At that short-burst protocol, v3 is again the only vector to disrupt a concurrent benign client (error 0.00 → 1.00). **v7 does not reproduce because SDK 1.30.0 is the patched release (≥1.25.2) for CVE-2026-0621** (~3 ms for a 50,000-character URI). This set does not re-run Table 3c's 10 s concurrent flood.

### 5.6 Practical high-concurrency flood (REAL, concurrent probe)

Table 3b's v2/v5 nulls were taken at concurrency ≤ 8 with the benign probe *after* a ~1 s burst. A deployed agent swarm does not look like that: many sessions stay open and keep calling while a flood is in progress. We therefore re-ran **v2 and v5 only**, pre-declared, on a second Windows host: **32 workers, 10 s sustained flood, established-session echo every 250 ms during the attack**, matched no-attack control of the same duration, n = 8 kept reps, order randomized. The Sec. 3 criterion is unchanged.

**Table 3c — Practical flood vs. no-attack control (REAL, concurrent established-session echo; C = 32, 10 s; n = 8; median [IQR] p95 in ms).** "Yes" is the Table 3b rule. RSS is mean peak MB.

| Vector | No-attack p95 | No-attack err | Attack p95 | Attack err | RSS ctrl→atk | MWU p (r) | §3 met? |
|---|---|---|---|---|---|---|---|
| v2 init/session flood | 8.96 [8.85, 9.12] | 0.00 | 49.28 [33.16, 125.72] | 0.00 | 53.4→176.9 | **0.0009** (+1.00) | **yes** |
| v5 tool-invocation flood | 6.56 [6.12, 7.29] | 0.00 | 64.14 [59.44, 66.62] | 0.00 | 70.9→246.0 | **0.0136** (+0.75) | **yes** |

Both tests survive Holm adjustment inside this two-test family (v2 corrected p = 0.0018; v5 remains 0.0136). v2 is a complete rank separation (U = 0): ~2,500–2,700 `initialize` calls succeed in 10 s, RSS triples and does not return to baseline inside the 8 s recovery cap, and an already-joined client's echo p95 rises **5.50×** (8.96 → 49.28 ms) with **zero** echo errors and **zero** new-`initialize` errors — degradation, not a hard deny. v5's 32 parallel tool sessions raise echo p95 **9.77×** (6.56 → 64.14 ms, r = +0.75; one of eight attack reps did not separate) and RSS 71 → 246 MB; CPU 3.4 → 46.3%. The original v2/v5 nulls are therefore a **measurement-regime result**, not evidence that network-reachable floods cannot hurt a live agent. C = 128 is still unmeasured.

---

## 6. Discussion

### 6.1 Mitigations and their cost

**Four mitigations produced a large, unambiguous reduction on their pre-specified channel** (v1, v2, v3, v6 peak RSS, each p = 0.0002, r −1.00). **v7** does the same on CPU (p = 0.0001, r −1.00) but that is an attacker-cost result, not availability. **v4** is a small CPU shift (2.97% → 2.46%, p = 0.037, r −0.56) on a load that never exhausted anything; we do not count it. **v5's pre-specified CPU test fails** (p = 0.186); the RSS drop and Table 3c latency rise are secondary observations, declared post-hoc for RSS. Under Holm–Bonferroni on the m = 7 pre-specified family, v1/v2/v3/v6 retain corrected p = 0.0011 and v7 p = 0.0006; v4 remains 0.037; v5's CPU result stays n.s.

**Three caveats.** *First, v4 is hardening by early rejection, not a demonstrated exhaustion vector.* *Second, v5 CPU stays on the record as a failed pre-specified test.* *Third, Table 3c is a separate family* (the anchors, second load points and cgroup re-runs are not mixed into it).

Two patterns generalize. First, **input-shape validation before expensive work is the cheapest and most effective mitigation class** — v1 (a pre-parser `413` body cap, −98.6% RSS growth), v3 (the SDK's own permissive `maxBufferSize` set to 2 MB, −100%: configuration, not code) and v7 (a length cap ahead of the vulnerable regex, −98.4% CPU), with v4's depth cap in the same family. Second, **rate limiting without client identity is the one mitigation class with a real, measured cost to legitimate users** (v2, v5: benign error rates 1.00 and 0.83) — the classic admission-control result: per-flow isolation and fair queueing, not aggregate limiting, protect well-behaved sources from a misbehaving one [30], [31], and session-granularity admission control preserves a serviceable subset of users where request-granularity shedding degrades everyone [33]; identity-less shedding is further undermined because source identity is spoofable [22]. A server should at least signal the shed with HTTP 429 [32].

### 6.2 Limitations and threats to validity

**Construct.** Table 3b's original probe is post-burst; calling it "concurrent" overstated the criterion. Table 3c fixes that for v2/v5 only. Recovery is RSS, not benign latency. v3 confounds pipe HOL blocking with allocation.

**Internal.** Warm-up makes several Table 3b attack arms *faster* than control. Table 3c randomizes control/attack order and still finds degradation. n = 8 on Table 3c (not 10). v5 Table 3c is not complete separation (r = +0.75).

**External.** Two Windows hosts, two SDK versions, loopback, servers we wrote plus one third-party reference server. Absolute milliseconds will move. C = 128, WAN RTT, and identity-aware rate limits are unmeasured. Table 3c was not repeated on `server-everything`.

**Conclusion.** A synthetic grid is in the artifact and is not evidence. We do not claim robustness at unmeasured concurrency. We do claim that a 32-worker, 10 s, in-flight flood is enough for v2 and v5 to meet the same availability rule that only v3 met at the short-burst anchors.

---

## 7. Ethics Considerations

**No non-consenting host or network was ever a target.** Every attack targeted a server this project started itself, bound explicitly to `127.0.0.1`; no non-loopback interface was opened. Every server ran under a hard RSS-ceiling watchdog and every attack subprocess under a wall-clock timeout, so a runaway attack could not itself become an incident. **Dual-use risk favors defenders:** all seven weakness classes are long-known, generic RPC/parser patterns (CWE-770, CWE-400, CWE-1333 [4], [5], [7]) with decades-old public precedent (Slowloris [6], algorithmic-complexity attacks [8]); every mitigation measured is a cheap deployment-side control; and the one vector with a real CVE (v7 / CVE-2026-0621 [16]) was public and patched before this project began. Mechanism-level, non-weaponized private-disclosure reports for the five CVE-less vectors were **filed** with the official SDK maintainers on **2026-08-20** — v1, v2, v4 with the Python SDK, v5, v6 with the TypeScript SDK — through each project's private security-advisory channel under an adopted **90-day coordinated-disclosure policy**; responses are pending. No IRB review was sought or claimed: every dependent variable is a property of a software process the authors ran on hardware they own, with no human subjects or PII.

---

## 8. Conclusion

Prior MCP security work names availability without measuring it on the official Python and TypeScript SDKs. This paper supplies CWE-mapped vectors, a locked experiment package, and replicated numbers. At short-burst anchors, only **v3** (local stdio) meets the concurrent-client criterion. Under a practical 32-worker, 10 s flood with the benign client running *during* the attack, **v2 and v5** meet the same criterion (5.50× and 9.77× established-echo p95) and grow RSS three-fold without returning to baseline in 8 s. Four input-shape or session caps cut the pre-specified resource channel; identity-less rate limits protect the process and collateral-reject legitimate callers; v4 is not an exhaustion result; v5's pre-specified CPU test fails. MCP inherits ordinary RPC resource-exhaustion weaknesses. The missing step is turning the cheap defenses on by default.

---

## Declarations

**Data and code availability.** Vector drivers, reference servers, cgroup-v2 definitions, analyzers and the labeled dataset underlie every table. `experiments/results/all_results.json` holds the original Windows/psutil plus synthetic rows (synthetic rows are labeled and are not used as evidence here). Table 3b uses `*__paired.json` / `*__paired_control.json`. Table 3c uses `*__practical.json` / `*__practical_control.json`, produced by `experiments/run_practical_flood.py` and summarized by `experiments/analyze_practical.py`. Source and data are at https://github.com/cybergeorge-science/mcp-resource-exhaustion . A citable archive DOI will be added upon acceptance. No third-party or proprietary data was used; every measurement targeted loopback-only servers on the authors' own hardware.

**Funding.** This research received no specific grant from any funding agency in the public, commercial, or not-for-profit sectors.

**Competing interests.** The authors declare no competing interests.

**Ethics and responsible disclosure.** See Section 7. Mechanism-level private-disclosure reports for the five vectors without a matching published CVE were filed with the Python SDK (v1, v2, v4) and TypeScript SDK (v5, v6) maintainers on 2026-08-20 under a 90-day coordinated-disclosure policy; maintainer responses are pending and any resulting timeline will be recorded.

---

## References

[1] Y. Yang, D. Wu, and Y. Chen, "MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols," arXiv:2508.13220, Aug. 2025.

[2] Model Context Protocol, "Specification" and "Architecture Overview," Model Context Protocol documentation, 2026.

[3] JSON-RPC Working Group, "JSON-RPC 2.0 Specification," 2013.

[4] MITRE, "CWE-770: Allocation of Resources Without Limits or Throttling," Common Weakness Enumeration, 2024.

[5] MITRE, "CWE-400: Uncontrolled Resource Consumption," Common Weakness Enumeration, 2024.

[6] R. Hansen, "Slowloris HTTP Denial of Service," technical advisory, ha.ckers.org, 2009.

[7] MITRE, "CWE-1333: Inefficient Regular Expression Complexity," Common Weakness Enumeration, 2024.

[8] S. A. Crosby and D. S. Wallach, "Denial of Service via Algorithmic Complexity Attacks," in *Proc. 12th USENIX Security Symp.*, 2003, pp. 29-44.

[9] M. H. M. Bhuiyan, B. Çakar, E. H. Burmane, J. C. Davis, and C.-A. Staicu, "SoK: A Literature and Engineering Review of Regular Expression Denial of Service (ReDoS)," in *Proc. 20th ACM ASIA CCS*, 2025, pp. 1659-1675.

[10] S. Gaire, S. Gyawali, S. Mishra, S. Niroula, D. Thakur, and U. Yadav, "Systematization of Knowledge: Security and Safety in the Model Context Protocol Ecosystem," arXiv:2512.08290, Dec. 2025.

[11] C. Huang, X. Huang, N. P. Tran, and A. Milani Fard, "Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning," arXiv:2603.22489, 2026.

[12] P. Sun, Z. Kang, Q. Jin, E. Huang, X. Liu, D. Shen, and S. Li, "VIPER-MCP: Detecting and Exploiting Taint-Style Vulnerabilities in Model Context Protocol Servers," arXiv:2605.21392, 2026.

[13] GitHub Security Advisories, GHSA-h669-8m4g-r2hc / CVE-2026-67432 — unbounded memory allocation on an oversized request body, modelcontextprotocol/ruby-sdk (fixed 0.23.0), 2026; cited as an out-of-scope, exact-mechanism analogue only.

[14] GitHub Security Advisories, GHSA-52jp-gj8w-j6xh / CVE-2026-67430 — idle sessions never reaped (`session_idle_timeout` defaults to nil), modelcontextprotocol/ruby-sdk, 2026; cited as an out-of-scope, exact-mechanism analogue only.

[15] GitHub Security Advisories, GHSA-7683-3w9x-ch42 / CVE-2026-63119 — unbounded read via `IO#gets` with no limit, modelcontextprotocol/ruby-sdk, 2026; cited as an out-of-scope, exact-mechanism analogue only.

[16] GitHub Security Advisory GHSA-cqwc-fm46-7fff (modelcontextprotocol/typescript-sdk repository advisory) / GitHub Advisory Database GHSA-8r9q-7v3j-jr4g / CVE-2026-0621 — catastrophic ReDoS in `UriTemplate.partToRegExp()`, @modelcontextprotocol/sdk (affected ≥1.3.0, <1.25.2; fixed 1.25.2; CVSS 8.7), published Jan. 5, 2026.

[17] GitHub Security Advisories, GHSA-j975-95f5-7wqh / CVE-2025-53365 — server crash from an uncaught `ClosedResourceError`, modelcontextprotocol/python-sdk (`mcp`<1.10.0; fixed 1.10.0; CVSS 8.7), 2025.

[18] GitHub Security Advisories, GHSA-3qhf-m339-9g5v / CVE-2025-53366 — FastMCP server validation-error crash, modelcontextprotocol/python-sdk (`mcp`<1.9.4; fixed 1.9.4; CVSS 8.7), 2025.

[19] AIS2Lab, "MCPSecBench," source-code repository, GitHub, 2026.

[20] J. Mirkovic and P. Reiher, "A taxonomy of DDoS attack and DDoS defense mechanisms," *ACM SIGCOMM Comput. Commun. Rev.*, vol. 34, no. 2, pp. 39–53, Apr. 2004.

[21] S. T. Zargar, J. Joshi, and D. Tipper, "A survey of defense mechanisms against distributed denial of service (DDoS) flooding attacks," *IEEE Commun. Surveys Tuts.*, vol. 15, no. 4, pp. 2046–2069, 2013.

[22] T. Peng, C. Leckie, and K. Ramamohanarao, "Survey of network-based defense mechanisms countering the DoS and DDoS problems," *ACM Comput. Surv.*, vol. 39, no. 1, art. 3, Apr. 2007.

[23] A. Klink and J. Wälde, "Effective denial of service attacks against web application platforms," presented at the 28th Chaos Communication Congress (28C3), Berlin, Germany, Dec. 2011.

[24] J.-P. Aumasson and D. J. Bernstein, "SipHash: A fast short-input PRF," in *Progress in Cryptology — INDOCRYPT 2012*, LNCS, vol. 7668. Berlin, Germany: Springer, 2012, pp. 489–508.

[25] J. C. Davis, C. A. Coghlan, F. Servant, and D. Lee, "The impact of regular expression denial of service (ReDoS) in practice: An empirical study at the ecosystem scale," in *Proc. 26th ACM ESEC/FSE*, 2018, pp. 246–256.

[26] C. Späth, C. Mainka, V. Mladenov, and J. Schwenk, "SoK: XML parser vulnerabilities," in *Proc. 10th USENIX Workshop Offensive Technol. (WOOT)*, Aug. 2016.

[27] B. Sullivan, "Security Briefs: XML denial of service attacks and defenses," *MSDN Magazine*, vol. 24, no. 11, Nov. 2009.

[28] MITRE, "CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')," Common Weakness Enumeration, 2024.

[29] T. Bray, Ed., "The JavaScript Object Notation (JSON) Data Interchange Format," RFC 8259, Internet Engineering Task Force, Dec. 2017.

[30] A. Demers, S. Keshav, and S. Shenker, "Analysis and simulation of a fair queueing algorithm," *ACM SIGCOMM Comput. Commun. Rev.*, vol. 19, no. 4, pp. 1–12, Aug. 1989.

[31] A. K. Parekh and R. G. Gallager, "A generalized processor sharing approach to flow control in integrated services networks: The single-node case," *IEEE/ACM Trans. Netw.*, vol. 1, no. 3, pp. 344–357, Jun. 1993.

[32] M. Nottingham and R. Fielding, "Additional HTTP Status Codes," RFC 6585, Internet Engineering Task Force, Apr. 2012.

[33] L. Cherkasova and P. Phaal, "Session-based admission control: A mechanism for peak load management of commercial web sites," *IEEE Trans. Comput.*, vol. 51, no. 6, pp. 669–685, Jun. 2002.

[34] A. Georges, D. Buytaert, and L. Eeckhout, "Statistically rigorous Java performance evaluation," in *Proc. 22nd ACM OOPSLA*, 2007, pp. 57–76.

[35] T. Kalibera and R. Jones, "Rigorous benchmarking in reasonable time," in *Proc. ACM Int. Symp. Memory Manage. (ISMM)*, 2013, pp. 63–74.

[36] E. D. Berger, S. M. Blackburn, M. Hauswirth, and M. Hicks, "Empirical evaluation guidelines (ACM SIGPLAN Empirical Evaluation Checklist)," ACM SIGPLAN, ver. Oct. 26, 2018.

[37] N. Cliff, "Dominance statistics: Ordinal analyses to answer ordinal questions," *Psychol. Bull.*, vol. 114, no. 3, pp. 494–509, 1993.
