"""
Real smoke-test driver for Vector 5 -- Tool-invocation flooding (CWE-400),
Streamable HTTP transport, TypeScript reference server.
"""
import json
import os
import shutil
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from common.schema import write_records
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX
from common.http_driver import run_one_http_smoke
from common.amplification import cpu_amplification

VECTOR = "v5_tool_flood"
SDK = "typescript"
PORT = 8816
LOAD_IDX = int(os.environ.get("SMOKE_LOAD_INDEX", ANCHOR_LOAD_INDEX[VECTOR]))
RATE_PER_S = LOAD_LEVELS[VECTOR]["values"][LOAD_IDX - 1]  # 400 req/s attempted at anchor
DURATION_S = 1.0
CONCURRENCY = 1  # one hammering session, sequential burst -- see attack.py
BASE_URL = f"http://127.0.0.1:{PORT}"

PY = sys.executable
NODE = shutil.which("node") or "node"
SERVER_SCRIPT = os.path.join(ROOT, "servers", "ts_http_server.mjs")
ATTACK_SCRIPT = os.path.join(os.path.dirname(__file__), "attack.py")

MIT_RATE = 20         # allow at most 20 tool calls per window
MIT_WINDOW_MS = 1000


def amp_fn(peak_rss, baseline_rss, mean_cpu, wall_duration_s, attack_result):
    # attacker cost proxy: wall-clock time the attacker script spent
    # producing+sending its (trivially cheap) requests
    attacker_cost_s = attack_result.get("elapsed_s", 0.0) * 0.01  # requests are ~sub-ms to build
    return cpu_amplification(mean_cpu, wall_duration_s, attacker_cost_s)


def one_run(mitigation: bool, no_attack: bool = False):
    server_env = {"MIT_INVOCATION_RATE": str(MIT_RATE) if mitigation else "0",
                  "MIT_INVOCATION_WINDOW_MS": str(MIT_WINDOW_MS)}
    attack_cmd = [PY, ATTACK_SCRIPT, BASE_URL, str(RATE_PER_S), str(DURATION_S), "3"]
    return run_one_http_smoke(
        vector=VECTOR, sdk=SDK, port=PORT, server_cmd=[NODE, SERVER_SCRIPT],
        server_env=server_env, attack_cmd=attack_cmd, no_attack=no_attack,
        load_level=LOAD_IDX, concurrency=CONCURRENCY,
        mitigation=mitigation, attack_timeout_s=30,
        amplification_fn=amp_fn,
        notes_extra=(f"rate_per_s={RATE_PER_S}, duration_s={DURATION_S}, "
                     f"mitigation_rate={MIT_RATE if mitigation else 'n/a'}/{MIT_WINDOW_MS}ms, "
                     f"amplification_channel=cpu_seconds"),
    )


if __name__ == "__main__":
    from common.reps import run_smoke_main
    run_smoke_main(VECTOR, one_run)
