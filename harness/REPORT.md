# Harness & MCPSecBench Integration — Report

## MCPSecBench upstream investigation (Phase 2)

Located and cloned the real repo — `https://github.com/AIS2Lab/MCPSecBench` (paper arXiv:2508.13220, Yang/Wu/Chen) — inspected it directly, then deleted the clone.

**Key finding, stated plainly:** there is no attack-module registry, plugin interface, or machine-readable per-run results schema in the real repo. `code/` is a flat set of standalone scripts (`main.py`, `client.py`, `mitm.py`, `squatting.py`, `maliciousadd.py`, `cve-2025-6514.py`, `index.js`) glued together by one orchestrator that drives GUI MCP hosts (Claude Desktop, Cursor) via `pyautogui`/`pwntools`, feeding prompts from `data/data.json` and asking the LLM under test to self-report `"Attack success"` / `"Attack detected"` / `"Protect Success"` into `data/experiments.csv` (manually verified, per `data/README.md`, which defines ASR/RR/PSR as the metrics).

MCPSecBench's 17 attacks are agent/LLM-level (prompt injection, tool poisoning, squatting, rug pull, sandbox escape, MITM, DNS rebinding, etc.) — nothing about transports, load levels, concurrency, latency, or resource sampling exists anywhere in it.

Since there's nothing upstream to match, `harness/dos_module/` implements a clean, conventional plugin architecture instead, with every file that defines it carrying an explicit "ASSUMED INTERFACE — verify against real MCPSecBench source before merging" docstring.

## Built, all under `C:\Users\giorgiia\mcp-paper\harness\`

- `dos_module/interface.py`, `registry.py`, `config.py`, `cli.py` — AttackModule ABC/registry/YAML+JSON-Schema config validation/CLI (`python -m dos_module.cli --list|--config PATH [--dry-run]`)
- `dos_module/vectors/*.py` — all 7 vector stubs registered with correct CWEs (oversized_body CWE-770, init_session_flood CWE-400, unbounded_stdio_stream CWE-770, deeply_nested_json CWE-770, tool_invocation_flooding CWE-400, slow_sse_slow_read CWE-400, redos_input_validation CWE-1333), each validating context (loopback-only, supported transports) then raising `NotImplementedError` — load generation is out of scope for this agent
- `dos_module/configs/run.example.yaml` (Listing 1, fully commented) + `config.schema.json` (JSON Schema)
- `measure/latency.py` (`LatencyRecorder`)
- `measure/benign_client.py` (`BenignClient`, steady-cadence synthetic load)
- `measure/sampler.py` (`ResourceSampler`, psutil-based, with an explicit documented-limitation docstring on Windows/psutil vs Linux cgroup `memory.peak`/`cpu.stat`, default 100ms interval)
- `measure/schema.py` (`RunRecord` + exact Table 6 JSON Schema)
- `measure/results_writer.py` (`build_run_record`, `write_json`, `append_jsonl`, `read_jsonl`, `compute_amplification`, `compute_recovery_s` — recovery threshold and amplification cost units flagged as placeholder FILL items per Phase 3)
- `tests/` — 37 pytest smoke tests, all synthetic input (no MCP server), covering latency percentiles, benign client rate/error/timeout behavior, sampler on both self-process and a real synthetic subprocess, results-writer round-trips + schema validation + recovery/amplification math, config validation (loopback rejection, unknown vector rejection, schema violations), CLI `--list`/`--dry-run`, and registry completeness.

## Test results

`python -m pytest tests/ -v` → **37 passed** in ~3s. Re-ran the timing-sensitive files 3x more with no flakes.

## Integration contract for the vector-implementation agent

Implement `AttackModule.run(ctx: AttackContext) -> AttackOutcome` in one of the 7 stub files; wrap it with `ResourceSampler.start()/stop()` and `BenignClient.start_background()/stop()` running concurrently, then call `build_run_record(...)` and `append_jsonl(record, path)`. The only real MCP-protocol code the harness expects the integrator to supply is a `request_fn: Callable[[], None]` (one request/response round trip via the Python `mcp` SDK or a bridge to the TypeScript SDK) and a target PID to attach the sampler to.

## Known gaps (documented, not hidden)

- No real attack traffic or live MCP target anywhere in this harness (by design)
- `pid_discovery` strategies are declared in the config schema but not implemented (no live target yet)
- Recovery threshold (110% of baseline) and amplification units (`bytes_sent`/`cpu_ms_target`) are explicit placeholders the paper must finalize
