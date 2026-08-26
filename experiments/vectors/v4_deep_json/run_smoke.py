"""
Real smoke-test driver for Vector 4 -- Deeply nested JSON (CWE-770),
Streamable HTTP transport, Python reference server.

Uses the CPU-channel amplification formula (see common/amplification.py):
this vector's dominant cost is parser CPU time, not sustained RSS growth.
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from common.schema import write_records
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX, ANCHOR_CONCURRENCY
from common.http_driver import run_one_http_smoke
from common.amplification import cpu_amplification

VECTOR = "v4_deep_json"
SDK = "python"
PORT = 8814
LOAD_IDX = int(os.environ.get("SMOKE_LOAD_INDEX", ANCHOR_LOAD_INDEX[VECTOR]))
CONCURRENCY = int(os.environ.get("SMOKE_CONCURRENCY", ANCHOR_CONCURRENCY))
DEPTH = LOAD_LEVELS[VECTOR]["values"][LOAD_IDX - 1]  # 1000 at anchor
BASE_URL = f"http://127.0.0.1:{PORT}"

PY = sys.executable
SERVER_SCRIPT = os.path.join(ROOT, "servers", "py_http_server.py")
ATTACK_SCRIPT = os.path.join(os.path.dirname(__file__), "attack.py")

MIT_MAX_DEPTH = 64  # generous for real MCP payloads, far below the depth-1000 attack


def amp_fn(peak_rss, baseline_rss, mean_cpu, wall_duration_s, attack_result):
    attacker_cpu_cost_s = attack_result.get("build_s", 0.0) * CONCURRENCY
    return cpu_amplification(mean_cpu, wall_duration_s, attacker_cpu_cost_s)


def one_run(mitigation: bool, no_attack: bool = False):
    server_env = {"MIT_JSON_MAX_DEPTH": str(MIT_MAX_DEPTH) if mitigation else "0"}
    attack_cmd = [PY, ATTACK_SCRIPT, BASE_URL, str(DEPTH), str(CONCURRENCY), "15"]
    return run_one_http_smoke(
        vector=VECTOR, sdk=SDK, port=PORT, server_cmd=[PY, SERVER_SCRIPT],
        server_env=server_env, attack_cmd=attack_cmd, no_attack=no_attack,
        load_level=LOAD_IDX, concurrency=CONCURRENCY,
        mitigation=mitigation, attack_timeout_s=30,
        amplification_fn=amp_fn,
        notes_extra=f"depth={DEPTH}, mitigation_max_depth={MIT_MAX_DEPTH if mitigation else 'n/a'}, "
                    f"amplification_channel=cpu_seconds",
    )


if __name__ == "__main__":
    from common.reps import run_smoke_main
    run_smoke_main(VECTOR, one_run)
