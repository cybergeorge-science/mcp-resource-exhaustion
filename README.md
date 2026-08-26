# MCP resource-exhaustion experiments

Measurement harness and loopback experiments for seven Model Context Protocol
(MCP) resource-exhaustion vectors against the official Python SDK (`mcp`) and
TypeScript SDK (`@modelcontextprotocol/sdk`).

This repository is the **experiment package** (code, servers, results). It is
not a paper repository.

> **Safety.** Every attack runs only against reference MCP servers this code
> starts itself, bound to `127.0.0.1`. Each server process has a hard RSS
> kill-switch and each attack a wall-clock timeout
> (`experiments/common/killswitch.py`). Do not point any driver at a host you
> do not own.

## Layout

```
harness/                    measurement helpers (schema, sampler, benign client, tests)
experiments/                reference servers, vector drivers, results, figures
  common/                   sampler, schema, killswitch, recovery, stats
  servers/                  py_* / ts_* servers (real SDKs, no stubs)
  vectors/v1..v7_*/         attack + run_smoke driver per vector
  run_replication.py        replicated OFF/ON smoke tests
  run_paired.py             within-session attack vs no-attack controls
  run_practical_flood.py    32-worker, 10 s concurrent-probe flood (v2, v5)
  results/real/*.json       real measurements (is_synthetic: false)
  results/synthetic/*.json  labeled model rows (is_synthetic: true; not evidence)
  figures/                  plots regenerated from results
```

## Requirements

- Python 3.12+ (`experiments/requirements.txt`, `harness/requirements.txt`):
  `mcp==1.27.0`, `psutil==7.2.2`, `httpx==0.28.1`, `jsonschema==4.26.0`,
  `pytest==8.3.3`.
- Node.js 24 with `@modelcontextprotocol/sdk==1.30.0`
  (`experiments/package.json`; `npm install` under `experiments/`).

```bash
pip install -r experiments/requirements.txt -r harness/requirements.txt
cd experiments && npm install
```

## Reproduce

```bash
# 1. tests
cd harness && python -m pytest -q
cd ../experiments && python -m pytest -q

# 2. replicated measurements (mean +/- 95% CI, n>=5, default 10)
python run_replication.py --reps 10
python run_replication.py --reps 10 --anchor2

# 3. OFF vs ON stats (Mann-Whitney U)
python analyze_replication.py

# 4. within-session no-attack controls
python run_paired.py --reps 10
python analyze_control.py

# 5. practical high-concurrency flood (v2, v5; C=32; 10 s; concurrent benign probe)
python run_practical_flood.py --reps 8
python analyze_practical.py

# 6. optional: labeled synthetic grid (illustration only)
python generate_synthetic.py
python validate_dataset.py
python figures/make_figures.py
```

Each `run_smoke.py` accepts `--reps N` (default 10), `--warmup`, `--cooldown`,
`--seed`, and `--tag`. It starts a fresh server per run, randomizes mitigation
OFF/ON order, discards a warm-up rep, and cools down between runs.

## Data honesty

Every result row carries `is_synthetic`. Real rows (`false`) are direct
measurements. Synthetic rows (`true`) are a documented power-law extrapolation
anchored to a real row (`anchor_run_id`). Do not treat synthetic rows as
observations.

## License

MIT (`LICENSE`).
