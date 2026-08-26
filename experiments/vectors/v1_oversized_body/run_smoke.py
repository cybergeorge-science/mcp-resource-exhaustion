"""
Real smoke-test driver for Vector 1 -- Oversized message body (CWE-770),
Streamable HTTP transport, Python reference server.

Runs the SAME attack (size_mb, concurrency fixed at the grid anchor) twice:
mitigation off, then mitigation on -- and writes two real (is_synthetic=
False) records to results/real/v1_oversized_body.json.
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from common.schema import write_records
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX, ANCHOR_CONCURRENCY
from common.http_driver import run_one_http_smoke

VECTOR = "v1_oversized_body"
SDK = "python"
PORT = 8811
LOAD_IDX = int(os.environ.get("SMOKE_LOAD_INDEX", ANCHOR_LOAD_INDEX[VECTOR]))
CONCURRENCY = int(os.environ.get("SMOKE_CONCURRENCY", ANCHOR_CONCURRENCY))
SIZE_MB = LOAD_LEVELS[VECTOR]["values"][LOAD_IDX - 1]
BASE_URL = f"http://127.0.0.1:{PORT}"

PY = sys.executable
SERVER_SCRIPT = os.path.join(ROOT, "servers", "py_http_server.py")
ATTACK_SCRIPT = os.path.join(os.path.dirname(__file__), "attack.py")

MIT_CAP_BYTES = 1 * 1024 * 1024  # 1 MB cap, well below the 10 MB attack payload


def one_run(mitigation: bool, no_attack: bool = False):
    server_env = {"MIT_BODY_CAP_BYTES": str(MIT_CAP_BYTES) if mitigation else "0"}
    attack_cmd = [PY, ATTACK_SCRIPT, BASE_URL, str(SIZE_MB), str(CONCURRENCY), "15"]
    return run_one_http_smoke(
        vector=VECTOR, sdk=SDK, port=PORT, server_cmd=[PY, SERVER_SCRIPT],
        server_env=server_env, attack_cmd=attack_cmd, no_attack=no_attack,
        load_level=LOAD_IDX, concurrency=CONCURRENCY,
        mitigation=mitigation, attack_timeout_s=30,
        notes_extra=f"size_mb={SIZE_MB}, mitigation_cap_bytes={MIT_CAP_BYTES if mitigation else 'n/a'}",
    )


if __name__ == "__main__":
    from common.reps import run_smoke_main
    run_smoke_main(VECTOR, one_run)
