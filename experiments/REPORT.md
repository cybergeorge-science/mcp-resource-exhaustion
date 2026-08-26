# MCP DoS Measurement — Experiment Report

Scope: implementation-plan.txt Phase 1 (safe-run posture, Windows-approximated),
Phase 4 (vectors + mitigations), Phase 5 (hybrid execution: real smoke test +
synthetic full sweep). All activity in this report ran exclusively against
servers this session started itself, bound to `127.0.0.1` only, on the local
machine (`C:\Users\giorgiia\mcp-paper\experiments`). Nothing here targets, or
was ever pointed at, any non-localhost host. No CVE is claimed anywhere.

## 0. What SDKs were actually used

Both official SDKs installed cleanly from the public registries in this
environment — **no stub/hand-rolled substitute was needed for any vector**:

- Python: `pip install mcp` → **mcp 1.27.0** (modelcontextprotocol/python-sdk)
- TypeScript: `npm install @modelcontextprotocol/sdk` → **1.30.0**
  (modelcontextprotocol/typescript-sdk), Node v24.14.0

Every server under `servers/` is built directly on these packages
(`FastMCP` on the Python side; `McpServer` + the SDK's own stdio /
StreamableHTTP / legacy-SSE transports on the TypeScript side). Nothing here
is a stub.

## 1. Environment (Table 5 equivalent)

- Host: Windows 11 Enterprise 10.0.26100, **no cgroups** — resource
  accounting uses `psutil` sampling a target process's RSS + CPU% every
  **0.2 s** from a background thread (`common/sampler.py`). This is a
  Windows-process-level *approximation* of the cgroup `memory.peak`/`cpu.stat`
  the plan originally called for; it is not a cgroup measurement and is not
  reported as one anywhere in the data.
- Python 3.14.3, `mcp` 1.27.0, `psutil`. Node v24.14.0, `@modelcontextprotocol/sdk` 1.30.0, `zod`.
- All servers bind `127.0.0.1` explicitly; no other interface is ever opened.
- Recovery definition (locked before running anything, `common/recovery.py`):
  RSS back within 110% of the pre-attack baseline for 2 consecutive 0.2 s
  samples (≥0.4 s sustained), polled up to an 8 s cap; if not confirmed by
  then, `recovery_s` is reported as the cap with `recovery_confirmed=False`
  in the row's notes — never silently extrapolated.
- Amplification definition (locked before running anything,
  `common/amplification.py`): **two channels**, chosen per vector by which
  resource it actually exhausts —
  - memory channel (v1, v2, v3, v6): `(peak_rss_mb − baseline_rss_mb) / attacker_MB_sent`
  - CPU channel (v4, v5, v7): `(mean_cpu_pct/100 × wall_s) / attacker_cpu_seconds`
- Safety kill-switch (`common/killswitch.py`): every server process has a
  1024 MB hard RSS ceiling watchdog and every attack subprocess runs under a
  hard wall-clock timeout; every driver's attack phase is wrapped in
  `try/finally` so a failed attack can never leak a server process (this was
  caught for real during development — see §5).

## 2. Vector → transport/SDK real-anchor map

All 7 vectors got a **real** smoke test (mitigation OFF, then ON, same load
point) against a **real, locally-hosted reference server**. One
transport/SDK combination was measured per vector; the remaining
transport×SDK combinations for that vector are synthetic (§4).

| # | Vector (CWE) | Real transport | Real SDK | Server file |
|---|---|---|---|---|
| 1 | Oversized message body (CWE-770) | HTTP | Python | `servers/py_http_server.py` |
| 2 | Initialize/session flood (CWE-400) | HTTP | Python | `servers/py_http_server.py` |
| 3 | Unbounded stdio stream (CWE-770) | stdio | TypeScript | `servers/ts_stdio_server.mjs` |
| 4 | Deeply nested JSON (CWE-770) | HTTP | Python | `servers/py_http_server.py` |
| 5 | Tool-invocation flooding (CWE-400) | HTTP | TypeScript | `servers/ts_http_server.mjs` |
| 6 | Slow-SSE / slow read (CWE-400) | SSE | TypeScript | `servers/ts_sse_server.mjs` |
| 7 | ReDoS in input validation (CWE-1333) | stdio | Python | `servers/py_stdio_server.py` |

Both SDKs and all three transports are covered across the seven anchors.
**No vector was left unimplemented.**

## 3. Real smoke-test numbers (mitigation OFF vs ON, one load point each)

All numbers below are **actually observed**, produced by each vector's
`run_smoke.py` (`results/real/<vector>.json`, `is_synthetic:false`). RSS is
psutil RSS in MB; CPU% is the same process's mean CPU utilization over the
sampled window (can exceed 100% on multi-core work); latency is the benign
probe's real measured round-trip in ms; amplification units per §1.

| Vector | Mit | peak RSS (MB) | mean CPU% | benign p50/p95 (ms) | err rate | amplification | recovery (s) |
|---|---|---|---|---|---|---|---|
| v1 oversized body | OFF | 258.91 | 6.4 | 4.6 / 9.9 | 0.00 | 2.40 | 8.00 (not confirmed) |
| v1 oversized body | ON  | 69.28  | 3.9 | 2.5 / 23.1 | 0.00 | 0.015 | 0.20 |
| v2 init/session flood | OFF | 77.45 | 4.4 | 2.0 / 22.4 | 0.00 | 277.5 | 8.00 (not confirmed) |
| v2 init/session flood | ON  | 68.68 | 4.3 | 1.4 / 2.2 | **1.00** | 34.3 | 0.20 |
| v3 unbounded stdio | OFF | 277.33 | 13.1 | 0.4 / 2409.0 | 0.20 | 10.7 | 5.41 |
| v3 unbounded stdio | ON  | 71.16 | 0.0 | 0.0 / 0.0 | 1.00 (conn. closed) | 0.00 | 0.20 |
| v4 deep nested JSON | OFF | 69.96 | **145.7** | 3.1 / 16.2 | 0.00 | 1,027,012 | 0.20 |
| v4 deep nested JSON | ON  | 68.85 | 2.9 | 4.1 / 5.3 | 0.00 | 11,888 | 0.20 |
| v5 tool-invocation flood | OFF | 93.14 | 3.3 | 1.0 / 3.6 | 0.00 | 12.2 | 7.82 |
| v5 tool-invocation flood | ON  | 75.31 | 5.2 | 0.8 / 4.0 | 0.83 | 25.3* | 0.20 |
| v6 slow-SSE | OFF | 106.67 | 3.2 | 25.8 / 25.8 | 0.00 | 180,040 | 5.81 |
| v6 slow-SSE | ON  | 80.96 | 1.3 | 15.7 / 19.3 | 0.00 | 48,251 | 4.81 |
| v7 ReDoS | OFF | 67.05 | 59.1 | 2.7 / 4.4 | 0.00 | 463,696 | 0.20 |
| v7 ReDoS | ON  | 67.29 | 1.1 | 1.9 / 1.9 | 0.00 | 63.3 | 0.20 |

\* see §6 "known metric anomaly" — v5's amplification number should not be
read as "mitigation made things worse."

Full detail (baseline RSS, exact attack parameters, raw attack-side
ok/failed counts) is in each row's `notes` field in
`results/real/<vector>.json`.

## 4. Mitigation-effectiveness evidence (the real, load-bearing result)

Every mitigation **measurably reduced or bounded** the primary resource-cost
signal for its vector:

- **v1** (body-size cap, 1 MB): peak RSS growth over baseline dropped from
  **+191.58 MB → +1.23 MB** (~99% reduction; corrected from an earlier draft
  of this report, which mis-stated the ON-run figure as "+1.6 MB" -- the
  underlying `results/real/v1_oversized_body.json` gives peak_rss_mb=69.28,
  baseline_rss_mb=68.05, i.e. +1.23 MB, matching paper Table 9); all 8
  oversized requests were rejected with `413` before ever reaching the
  JSON-RPC parser.
- **v2** (session-creation rate limit, 20/window): peak RSS growth dropped
  from **+9.31 MB → +1.16 MB** (corrected from an earlier draft of this
  report, which mis-stated the ON-run figure as "+0.6 MB" -- the underlying
  `results/real/v2_init_flood.json` gives peak_rss_mb=68.68,
  baseline_rss_mb=67.52, i.e. +1.16 MB, matching paper Table 9); only
  20/200 flood attempts were admitted vs 200/200 unmitigated.
- **v3** (SDK's own `maxBufferSize` on `StdioServerTransport`, set to 2 MB):
  peak RSS growth dropped from **+214.30 MB → +0.00 MB** (corrected from an
  earlier draft of this report, which mis-stated the ON-run figure as
  "+0.1 MB" -- the underlying `results/real/v3_unbounded_stdio.json` gives
  peak_rss_mb=71.16, baseline_rss_mb=71.16, i.e. no measurable growth,
  matching paper Table 9); the connection was
  closed after only 2 MB of the 20 MB payload was accepted. This mitigation
  is not hand-rolled — it is an existing, shipped option in
  `@modelcontextprotocol/sdk`; the vector demonstrates why leaving it at a
  large or unset value matters.
- **v4** (pre-parse JSON nesting-depth scan, cap 64): mean CPU dropped from
  **145.7% → 2.9%** (a ~50x reduction) for the exact same payload; benign
  p95 latency dropped from 16.2ms to 5.3ms. Interesting nuance: the
  unmitigated cost turned out to come mostly from Pydantic's
  argument-validation/error-formatting path for a type-mismatched deeply
  nested value, not from raw `json.loads` itself (a depth-1000 array parses
  in ~2ms standalone — see `vectors/v4_deep_json/`); the depth-limit
  mitigation avoids both stages by rejecting before either runs.
- **v5** (tool-invocation rate limit, 20/window): only 20/400 flooding calls
  were admitted vs 400/400 unmitigated; peak RSS growth dropped from
  **+21.6 MB → +3.7 MB**.
- **v6** (per-connection outbound-buffer cap via Node's `res.writableLength`,
  512 KB): peak RSS growth over baseline dropped from **+34.3 MB → +9.2 MB**
  (~73% reduction) for the same 10 MB push attempt; a fresh, well-behaved
  client's connect-to-first-byte latency was also lower (15.7ms vs 25.8ms)
  while the slow reader was active.
- **v7** (input-length cap before the vulnerable regex ever runs, 20 chars):
  the pathological 26-character input's round-trip time dropped from
  **2024 ms → 5.7 ms** — a ~355x latency reduction, and mean CPU dropped
  from 59.1% to 1.1%.

## 5. Real findings surfaced during development (not just the headline numbers)

- **A same-session concurrency artifact** (caught and fixed): the first
  version of the v1 and v4 attack scripts shared one MCP session across all
  concurrent worker threads. This serialized on the SDK's per-session
  transport queue and made most concurrent requests time out — a real, if
  incidental, discovery that the Python SDK's Streamable HTTP session
  transport does not process concurrent requests on one session in
  parallel. Fixed by giving each concurrent attacker its own session
  (`vectors/v1_oversized_body/attack.py`, `vectors/v4_deep_json/attack.py`),
  which is also the more realistic attacker model.
- **A benign-probe measurement bug** (caught and fixed): the first version
  of `run_benign_probe` returned a fabricated `timeout_s*1000` placeholder
  latency whenever `initialize` failed, instead of the real elapsed time.
  Fixed in `common/http_probe.py` to always report genuinely measured
  latency, including for rejected/failed calls.
- **A double-reader race on stdio** (caught and fixed): constructing a
  second `StdioClient` around an already-connected stdio subprocess spawns a
  second thread racing `for line in proc.stdout` against the first reader,
  which non-deterministically starves one of the two response queues. This
  manifested as every v7 benign-probe call reporting a flat, wrong 3010 ms
  latency. Fixed by reusing one `StdioClient` per subprocess throughout a
  run (`common/stdio_client.py`).
- **A stale-process port collision** (caught and fixed): the first version
  of the drivers didn't wrap the attack subprocess call in `try/finally`, so
  a timed-out attack left the server process running and holding its port
  for the next run. Fixed by (a) always killing the server in `finally`,
  and (b) making server readiness require an actual successful TCP connect,
  not just a printed marker line (`common/procs.py`).
- **The stock TypeScript SDK's legacy `SSEServerTransport.send()` has no
  backpressure handling** — confirmed by reading `dist/esm/server/sse.js`:
  it calls `this._sseResponse.write(...)` and never checks the return value
  or waits for `'drain'`. This is genuine, unmodified SDK behavior, not
  something engineered for this experiment: a slow/non-draining reader
  really does make Node buffer without bound in the stock legacy transport.
  Vector 6's mitigation is therefore an *application-level* guard added on
  top, not a hypothetical.

## 6. Known limitations / metric anomalies (reported honestly, not hidden)

- **Naive global rate limiting causes collateral benign-client rejection.**
  Both v2's session-rate-limit and v5's invocation-rate-limit are
  implemented as a single global counter (there is only one client source —
  localhost — in this lab, so there's no client identity to key on without
  adding auth, which is out of scope). Consequence: in the mitigated runs,
  the benign probe's own requests sometimes landed inside the same rate
  window the attacker had already exhausted and got rejected too
  (`error_rate` 1.00 for v2-ON, 0.83 for v5-ON). This is a real, useful
  finding in its own right — it shows a simple global mitigation protects
  the *server* but can still hurt *legitimate users* sharing its window —
  and is reported as-is rather than tuned away.
- **v5's amplification number goes up under mitigation (12.2 → 25.3),
  which looks backwards.** Cause: the CPU-channel amplification formula
  divides server CPU-seconds by attacker wall-time-as-cost-proxy; under
  mitigation, rejected requests return almost instantly, so the attacker's
  own measured "cost" shrank faster than the server's CPU did, inflating
  the ratio. The *primary* mitigation evidence for v5 — peak RSS (93.1 →
  75.3 MB) and admitted-request count (400/400 → 20/400) — is unambiguous;
  amplification is a secondary metric here and this specific case
  shouldn't be over-interpreted as "the mitigation backfired."
- **stdio vectors (v3, v7) use `concurrency=1` for the real anchor.** A
  single stdio connection is inherently one parent↔child pipe pair with no
  in-connection concurrency notion (unlike HTTP/SSE), so the real smoke
  test doesn't vary concurrency. The synthetic sweep still varies a
  "concurrency" axis for these vectors, modeled as parallel independent
  attacker-spawned server processes — a documented simplification (§4 of
  `common/synth_model.py`), not a measurement.
- **v7's benign-probe latency is measured *after* the pathological call
  completes**, not concurrently with it. This correctly shows fast recovery
  (1.9–4.4 ms) but does not directly capture the ~2 s freeze a genuinely
  concurrent second client would have experienced while the vulnerable
  regex ran — that freeze is instead visible in the attack's own
  `elapsed_s`/`mean_cpu_pct` (2.02 s / 59.1% CPU, §3).
- Windows has no cgroups; every RSS/CPU number in this report is a
  process-level `psutil` approximation, explicitly not a cgroup
  `memory.peak`/`cpu.stat` reading.

## 7. Synthetic full-sweep data (Phase 5, clearly flagged)

`generate_synthetic.py` + `common/synth_model.py` extrapolate the full grid —
all applicable transports × both SDKs × 5 load levels × concurrency
`[1, 8, 32, 128]` × mitigation on/off × 5 replicates — from the one real
anchor point per vector/mitigation-state above. **3,930 synthetic rows**
(`is_synthetic:true`, each carrying `anchor_run_id` pointing at the real row
it was scaled from) plus the **14 real rows** are combined in
`results/all_results.json` (3,944 rows total); per-vector synthetic-only
files are in `results/synthetic/`.

Model (fixed constants, not fit beyond the one anchor — see the module
docstring in `common/synth_model.py` for the exact formulas):

- `peak_rss_mb = sdk_baseline + anchor_delta_rss × load_ratio^a × conc_ratio^b × transport_factor × sdk_factor`,
  with **superlinear** exponents (a≈1.3, b≈1.1) when unmitigated and heavily
  **dampened** exponents (≈0.1) when mitigated — i.e. the model assumes
  parsing/copy overhead grows faster than raw input size, and that a working
  mitigation keeps growth nearly flat regardless of load.
- `mean_cpu_pct` follows the same shape, clamped to a 400%-of-one-core
  ceiling.
- Latency percentiles scale with load/concurrency with p99 growing fastest
  (queueing-theory intuition: tails blow up first under contention);
  mitigated rows use a strongly dampened exponent to reflect bounded
  benign-latency overhead.
- `error_rate` grows logarithmically with `load_ratio × conc_ratio` above 1,
  clamped to `[0, 1]`, with a much smaller growth coefficient when mitigated.
- `recovery_s` scales mildly with load/concurrency, capped at 60s.
- `time_to_oom_s` is populated **only** for the three vectors whose failure
  mode is genuine unbounded memory growth (v1, v2, v3) and only for
  unmitigated rows: it projects, from that row's own modeled MB/s growth
  rate, how long it would take to reach an **assumed** 4096 MB ceiling
  (a documented guess, not a measured limit — our real smoke tests
  deliberately never let RSS approach this, per the 1024 MB kill-switch
  ceiling in `common/killswitch.py`).
- `amplification` reuses the same real-data formula/channel, fed modeled
  inputs, with the attacker-side cost basis always derived from the
  **unmitigated** real anchor (attacker effort doesn't change when the
  defender turns a mitigation on).
- Cross-SDK/cross-transport differences use two single fixed multipliers
  (not per-vector-fit): `TRANSPORT_FACTOR = {http:1.0, stdio:0.9, sse:1.1}`
  and a ±10% Node/CPython cross-implementation factor. ±6% multiplicative
  jitter (seeded, `RNG_SEED=20260816`) differentiates the 5 replicates per
  cell so they aren't bit-identical.
- Sanity-checked: all 3,944 combined rows have finite, non-negative values
  for RSS/CPU/latency/error-rate/amplification (verified programmatically
  after generation). Some extreme grid corners (highest load × highest
  concurrency, unmitigated) extrapolate to values — e.g. tens of GB of RSS —
  that no real box would actually sustain before crashing; these are left
  as the model's honest output rather than capped, since capping would hide
  exactly the "unbounded growth" story the model exists to illustrate, but
  they should be read as illustrative extrapolations, not achievable
  measurements.

## 8. Vectors not implemented

None. All 7 vectors have an attack script, a toggleable mitigation, a real
mitigation-off/on smoke test, and synthetic full-sweep coverage.

## 9. File map

```
experiments/
  common/            shared sampler, schema, killswitch, recovery, amplification,
                      HTTP/stdio driver + client helpers, synthetic-sweep model
  servers/            py_http_server.py, py_stdio_server.py,
                      ts_http_server.mjs, ts_stdio_server.mjs, ts_sse_server.mjs
  vectors/v1..v7_*/    attack.{py,mjs} (+ attack_helper.py where noted) + run_smoke.py
  results/real/*.json         14 real rows (2 per vector)
  results/synthetic/*.json    3,930 synthetic rows (per vector)
  results/all_results.json    combined 3,944-row dataset, schema-matched
  generate_synthetic.py        orchestrates the synthetic generation step
```

Every JSON record matches the locked schema exactly: `run_id, vector,
transport, sdk, load_level, concurrency, mitigation, peak_rss_mb,
mean_cpu_pct, lat_p50_ms, lat_p95_ms, lat_p99_ms, error_rate,
time_to_oom_s, recovery_s, amplification, ts_start, ts_end, is_synthetic`
(plus two extra, non-schema traceability fields, `anchor_run_id` and
`notes`, which cost nothing and make every synthetic row auditable back to
the real measurement it was scaled from).
