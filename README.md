# Denial of Service as a First-Class MCP Security Property

Threat model, CWE-grounded taxonomy, standalone measurement harness, and
empirical evaluation of seven denial-of-service (DoS) vectors against the two
official Model Context Protocol (MCP) SDKs (Python `mcp`, TypeScript
`@modelcontextprotocol/sdk`).

This repository is the reproducibility artifact for the paper
(`paper_draft.md`, built to `mcp-dos-paper-FILLED.docx` via `build_docx.py`).

> **Safety / ethics.** Every attack in this project runs *only* against
> reference MCP servers this code starts itself, bound to `127.0.0.1`.
> Each server process runs under a hard RSS kill-switch and each attack under a
> wall-clock timeout (`experiments/common/killswitch.py`). Do not point any
> driver at a host you do not own. See paper Section 8 (Ethics) and
> `disclosures/` for the responsible-disclosure posture.

## Layout

```
paper_draft.md              source of truth for the paper (edit here, then rebuild)
build_docx.py               paper_draft.md -> mcp-dos-paper-FILLED.docx
harness/                    standalone measurement harness (AttackModule interface,
                            locked run-record schema, sampler, benign client, tests)
experiments/                reference servers, vector drivers, results, figures
  common/                   sampler, schema, killswitch, recovery, amplification,
                            synth_model, stats (P1.1), reps (P1.1)
  servers/                  py_* / ts_* reference MCP servers (real SDKs, no stubs)
  vectors/v1..v7_*/         attack + run_smoke driver per vector
  results/real/*.json       replicated real measurements (is_synthetic:false)
  results/synthetic/*.json  labeled synthetic full-sweep (is_synthetic:true)
  results/all_results.json  combined dataset, validated against the locked schema
  figures/                  Figures 2-4 + make_figures.py
disclosures/                drafted (not filed) private-disclosure reports
reviews/                    review + improvement-plan documents
```

## Requirements

- Python 3.14 (`experiments/requirements.txt`, `harness/requirements.txt` are
  exact-pinned to the versions used: `mcp==1.27.0`, `psutil==7.2.2`,
  `httpx==0.28.1`, `matplotlib==3.11.0`, `jsonschema==4.26.0`, `PyYAML==6.0.2`,
  `pytest==8.3.3`, `numpy`).
- Node.js 24 with `@modelcontextprotocol/sdk==1.30.0` (`experiments/package.json`,
  exact-pinned; `npm install` under `experiments/`).

```bash
pip install -r experiments/requirements.txt -r harness/requirements.txt
cd experiments && npm install
```

## Reproduce

```bash
# 1. tests
cd harness && python -m pytest -q          # 37 tests
cd ../experiments && python -m pytest -q    # regression + stats tests

# 2. real, replicated measurements (P1.1: mean +/- 95% CI over >=5 reps/cell)
python run_replication.py --reps 10                 # primary anchor, all 7 vectors
python run_replication.py --reps 10 --anchor2       # second load point (P1.2)

# 3. per-cell statistics + Mann-Whitney U (OFF vs ON)
python analyze_replication.py                        # -> results/stats_summary.json

# 4. synthetic full sweep (labeled is_synthetic:true) + combined dataset
python generate_synthetic.py

# 5. validate the whole dataset against the locked schema (zero errors)
python validate_dataset.py

# 6. figures
python figures/make_figures.py

# 7. practical high-concurrency flood (Table 3c; v2 and v5, C=32, 10 s,
#    concurrent benign probe; does not overwrite the committed anchors)
python run_practical_flood.py --reps 8
python analyze_practical.py
```

Each `run_smoke.py` accepts `--reps N` (default 10, minimum 5), `--warmup`,
`--cooldown`, `--seed`, and `--tag`; it starts a fresh server per run,
randomizes mitigation OFF/ON order, discards a warm-up rep, and cools down
between runs.

## Data honesty

Every result row carries `is_synthetic`. Real rows (`false`) are direct
measurements; synthetic rows (`true`) are a documented power-law extrapolation
anchored to a real row (`anchor_run_id`). No table or figure blends the two
without a label. See paper Section 4.4 and Section 6.

## Artifact status

Code and data exist and run locally. Public archival + DOI are **prepared but
pending** (see `CITATION.cff` and paper Appendix A): the repository is ready to
push and to mint a Zenodo DOI against the tagged commit, but has not yet been
published externally.

## License

MIT (`LICENSE`).
