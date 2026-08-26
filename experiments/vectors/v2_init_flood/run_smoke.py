"""
Real smoke-test driver for Vector 2 -- Initialize/session flood (CWE-400),
Streamable HTTP transport, Python reference server.
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from common.schema import write_records
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX, ANCHOR_CONCURRENCY
from common.http_driver import run_one_http_smoke

VECTOR = "v2_init_flood"
SDK = "python"
PORT = 8812
LOAD_IDX = int(os.environ.get("SMOKE_LOAD_INDEX", ANCHOR_LOAD_INDEX[VECTOR]))
CONCURRENCY = int(os.environ.get("SMOKE_CONCURRENCY", ANCHOR_CONCURRENCY))
RATE_PER_S = LOAD_LEVELS[VECTOR]["values"][LOAD_IDX - 1]  # 200 req/s attempted at anchor
DURATION_S = 1.0
BASE_URL = f"http://127.0.0.1:{PORT}"

PY = sys.executable
SERVER_SCRIPT = os.path.join(ROOT, "servers", "py_http_server.py")
ATTACK_SCRIPT = os.path.join(os.path.dirname(__file__), "attack.py")

MIT_SESSION_RATE = 20        # allow at most 20 new sessions per window
MIT_SESSION_WINDOW_S = 1.0


def one_run(mitigation: bool, no_attack: bool = False):
    server_env = {"MIT_SESSION_RATE": str(MIT_SESSION_RATE) if mitigation else "0",
                  "MIT_SESSION_WINDOW_S": str(MIT_SESSION_WINDOW_S)}
    attack_cmd = [PY, ATTACK_SCRIPT, BASE_URL, str(RATE_PER_S), str(DURATION_S), str(CONCURRENCY), "3"]
    return run_one_http_smoke(
        vector=VECTOR, sdk=SDK, port=PORT, server_cmd=[PY, SERVER_SCRIPT],
        server_env=server_env, attack_cmd=attack_cmd, no_attack=no_attack,
        load_level=LOAD_IDX, concurrency=CONCURRENCY,
        mitigation=mitigation, attack_timeout_s=60,
        notes_extra=(f"rate_per_s={RATE_PER_S}, duration_s={DURATION_S}, "
                     f"mitigation_rate={MIT_SESSION_RATE if mitigation else 'n/a'}/"
                     f"{MIT_SESSION_WINDOW_S if mitigation else ''}s"),
    )


if __name__ == "__main__":
    from common.reps import run_smoke_main
    run_smoke_main(VECTOR, one_run)
