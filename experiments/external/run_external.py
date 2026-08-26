"""
External-validity experiment (final-corrections task #1).

Runs the SAME attack modules against a REAL third-party MCP server we did NOT
write -- @modelcontextprotocol/server-everything, the MCP maintainers' own
reference server, installed pinned in external/node_modules -- instead of this
project's reference servers. Everything is loopback-only; each server is a fresh
process; the existing RSS-ceiling watchdog and wall-clock timeouts stay on.

For each vector we measure two arms at the paper's anchor load:
  * baseline : server up, benign probe running, attack NOT invoked (no_attack)
  * attack   : the unmitigated attack in progress
and ask whether the weakness REPRODUCES on a server we didn't author, i.e.
whether the vector's primary resource channel (RSS or CPU) and/or the benign
client move adversely under attack vs. the no-attack baseline.

server-everything ships NO deployment-side mitigations, so this measures
weakness-presence (attack vs no-attack), which is exactly what external validity
needs -- not OFF/ON mitigation efficacy (that stays in Table 3).

Every row is a real measurement (is_synthetic=False). Nothing here is modeled.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)

import json as _json
import subprocess
from common import stats
from common.sampler_cgroup import make_sampler
from common.schema import Record, percentiles
from common.procs import _port_open
from common.recovery import wait_for_recovery
from common.http_probe import run_benign_probe
from common.killswitch import kill_tree
from common.amplification import mem_amplification

PY = sys.executable
NODE = "node"
EXT_INDEX = os.path.join(HERE, "node_modules", "@modelcontextprotocol",
                         "server-everything", "dist", "index.js")
VEC = os.path.join(ROOT, "vectors")
OUT = os.path.join(HERE, "results")
REPS = 8
WARMUP = 1

# anchor params (mirror common/grid at anchor load index)
HTTP_VECTORS = {
    "v1_oversized_body": dict(
        port=8901, channel="rss",
        attack=lambda u: [PY, os.path.join(VEC, "v1_oversized_body", "attack.py"), u, "10", "8", "15"]),
    "v2_init_flood": dict(
        port=8902, channel="rss",
        attack=lambda u: [PY, os.path.join(VEC, "v2_init_flood", "attack.py"), u, "200", "1.0", "8", "3"]),
    "v4_deep_json": dict(
        port=8903, channel="cpu",
        attack=lambda u: [PY, os.path.join(VEC, "v4_deep_json", "attack.py"), u, "1000", "8", "15"]),
    "v5_tool_flood": dict(
        port=8904, channel="rss",
        attack=lambda u: [PY, os.path.join(VEC, "v5_tool_flood", "attack.py"), u, "400", "1.0", "3"]),
}


def _parse_body(r):
    if "text/event-stream" in r.headers.get("content-type", ""):
        for ln in r.text.splitlines():
            if ln.startswith("data:"):
                try:
                    return _json.loads(ln[5:].strip())
                except Exception:
                    return None
        return None
    try:
        return r.json()
    except Exception:
        return None


def run_benign_probe_ext(url, n=5, timeout_s=3.0):
    """Benign probe matching server-everything's echo schema ({message}), with
    real measured latency on every attempt. Returns (latencies_ms, error_rate)."""
    import httpx
    c = httpx.Client(timeout=timeout_s)
    h = {"Content-Type": "application/json",
         "Accept": "application/json, text/event-stream"}
    lat = []; err = 0
    t0 = time.perf_counter()
    try:
        r = c.post(f"{url}/mcp", headers=h, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "benign-probe", "version": "1.0"}}})
        lat.append((time.perf_counter() - t0) * 1000)
        if r.status_code != 200:
            err += 1
        sid = r.headers.get("mcp-session-id")
        if sid:
            h["mcp-session-id"] = sid
        c.post(f"{url}/mcp", headers=h,
               json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    except Exception:
        lat.append((time.perf_counter() - t0) * 1000); err += 1
    for i in range(n):
        t0 = time.perf_counter()
        try:
            r = c.post(f"{url}/mcp", headers=h, json={
                "jsonrpc": "2.0", "id": 2 + i, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "benign-probe"}}})
            lat.append((time.perf_counter() - t0) * 1000)
            b = _parse_body(r)
            ok = (r.status_code == 200 and b is not None and "error" not in b
                  and not (b.get("result") or {}).get("isError"))
            if not ok:
                err += 1
        except Exception:
            lat.append((time.perf_counter() - t0) * 1000); err += 1
    c.close()
    tot = len(lat)
    return lat, (err / tot if tot else 0.0)


def _one_http(name, cfg, no_attack):
    """Self-contained one-run for the external HTTP server: launch
    server-everything, wait for the port (it prints no READY marker), sample
    RSS/CPU, run the attack (unless no_attack) + benign probe, recover, kill."""
    port = cfg["port"]; url = f"http://127.0.0.1:{port}"
    env = dict(os.environ, PORT=str(port))
    proc = subprocess.Popen([NODE, EXT_INDEX, "streamableHttp"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and not _port_open("127.0.0.1", port):
        if proc.poll() is not None:
            raise RuntimeError(f"[{name}] server exited before listen")
        time.sleep(0.1)
    if not _port_open("127.0.0.1", port):
        kill_tree(proc.pid); raise RuntimeError(f"[{name}] server not ready")
    sampler = make_sampler(proc.pid)
    try:
        sampler.start(); time.sleep(1.0)
        base = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0
        if not no_attack:
            try:
                subprocess.run(cfg["attack"](url), capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                pass
        lat, err = run_benign_probe_ext(url, n=5, timeout_s=3.0)
        wait_for_recovery(proc.pid, base)
        peak = sampler.series.peak_rss_mb; cpu = sampler.series.mean_cpu_pct
    finally:
        sampler.stop(); kill_tree(proc.pid); time.sleep(0.3)
    p50, p95, p99 = percentiles(lat)
    return Record(vector=name, transport="http", sdk="server-everything",
                  load_level=3, concurrency=8, mitigation=False,
                  peak_rss_mb=round(peak, 2), mean_cpu_pct=round(cpu, 2),
                  lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
                  error_rate=round(err, 3), ts_start=0.0, ts_end=0.0, is_synthetic=False,
                  notes=(f"EXTERNAL server-everything; arm={'baseline' if no_attack else 'attack'}; "
                         f"baseline_rss_mb={base:.2f}; attack_present={'no' if no_attack else 'yes'}"))


def run_http_arm(name, cfg, no_attack):
    recs = []
    arm = "baseline" if no_attack else "attack"
    for i in range(REPS + WARMUP):
        rec = _one_http(name, cfg, no_attack)
        print(f"[{name}/{arm}] {'warmup' if i < WARMUP else f'rep {i-WARMUP}'} "
              f"rss={rec.peak_rss_mb} cpu={rec.mean_cpu_pct} p95={rec.lat_p95_ms} "
              f"err={rec.error_rate}", flush=True)
        if i >= WARMUP:
            recs.append(rec)
        time.sleep(1.0)
    return recs


def run_v3_stdio():
    """Unbounded-stdio (CWE-770) against server-everything's stdio transport,
    whose SDK StdioServerTransport maxBufferSize defaults permissively."""
    sys.path.insert(0, os.path.join(VEC, "v3_unbounded_stdio"))
    from common.sampler_cgroup import make_sampler
    from common.schema import Record, percentiles
    from common.stdio_launch import start_stdio_server
    from common.stdio_client import StdioClient
    from common.recovery import wait_for_recovery
    from common.killswitch import kill_tree
    from attack_helper import send_unbounded_line
    SIZE_MB = 20

    def probe(client):
        """Benign stdio probe using server-everything's echo schema ({message})."""
        lat = []; err = 0
        for i in range(5):
            t0 = time.perf_counter()
            try:
                ok, dt, _ = client.call_tool("echo", {"message": "benign-probe"},
                                             req_id=100 + i, timeout_s=3.0)
            except Exception:
                ok, dt = False, (time.perf_counter() - t0) * 1000
            lat.append(dt)
            if not ok:
                err += 1
        return lat, (err / len(lat) if lat else 0.0)

    def one(no_attack):
        handle = start_stdio_server([NODE, EXT_INDEX, "stdio"], env=dict(os.environ),
                                    ready_prefix="Starting default (STDIO) server",
                                    timeout_s=10)
        if not handle.ready:
            kill_tree(handle.pid)
            raise RuntimeError(f"server not ready: {handle.stderr_lines}")
        sampler = make_sampler(handle.pid)
        try:
            sampler.start(); time.sleep(1.0)
            base = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0
            client = StdioClient(handle.proc)
            ok, _ = client.initialize(timeout_s=5.0)
            if not ok:
                raise RuntimeError("stdio initialize failed")
            if no_attack:
                lat, err = probe(client)
            else:
                ar = send_unbounded_line(handle.proc, SIZE_MB)
                if ar.get("aborted"):
                    lat, err = [0.0] * 6, 1.0
                else:
                    lat, err = probe(client)
            wait_for_recovery(handle.pid, base)
            peak = sampler.series.peak_rss_mb; cpu = sampler.series.mean_cpu_pct
        finally:
            sampler.stop(); kill_tree(handle.pid); time.sleep(0.3)
        p50, p95, p99 = percentiles(lat)
        return Record(vector="v3_unbounded_stdio", transport="stdio", sdk="server-everything",
                      load_level=3, concurrency=1, mitigation=False,
                      peak_rss_mb=round(peak, 2), mean_cpu_pct=round(cpu, 2),
                      lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
                      error_rate=round(err, 3), ts_start=0.0, ts_end=0.0, is_synthetic=False,
                      notes=f"EXTERNAL server-everything stdio; baseline_rss_mb={base:.2f}")

    out = {}
    for arm, na in (("baseline", True), ("attack", False)):
        recs = []
        for i in range(REPS + WARMUP):
            r = one(na)
            print(f"[v3_unbounded_stdio/{arm}] {'warmup' if i < WARMUP else f'rep {i-WARMUP}'} "
                  f"rss={r.peak_rss_mb} cpu={r.mean_cpu_pct} p95={r.lat_p95_ms} err={r.error_rate}", flush=True)
            if i >= WARMUP:
                recs.append(r)
            time.sleep(1.0)
        out[arm] = recs
    return out


def run_v6_sse():
    """Slow-SSE / slow-read (CWE-400) against server-everything's SSE transport."""
    sys.path.insert(0, os.path.join(VEC, "v6_slow_sse"))
    from attack_helper import open_slow_reader, benign_sse_probe
    port = 8906; host = "127.0.0.1"

    def one(no_attack):
        env = dict(os.environ, PORT=str(port))
        proc = subprocess.Popen([NODE, EXT_INDEX, "sse"], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not _port_open(host, port):
            if proc.poll() is not None:
                raise RuntimeError("v6 server exited before listen")
            time.sleep(0.1)
        sampler = make_sampler(proc.pid); sock = None
        try:
            sampler.start(); time.sleep(1.0)
            base = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0
            if not no_attack:
                try:
                    sock, _ = open_slow_reader(host, port)
                except Exception:
                    sock = None
            time.sleep(2.5)
            lat, err = benign_sse_probe(host, port, n=3, timeout_s=3.0)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            wait_for_recovery(proc.pid, base)
            peak = sampler.series.peak_rss_mb; cpu = sampler.series.mean_cpu_pct
        finally:
            sampler.stop(); kill_tree(proc.pid); time.sleep(0.3)
        p50, p95, p99 = percentiles(lat)
        return Record(vector="v6_slow_sse", transport="sse", sdk="server-everything",
                      load_level=3, concurrency=1, mitigation=False,
                      peak_rss_mb=round(peak, 2), mean_cpu_pct=round(cpu, 2),
                      lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
                      error_rate=round(err, 3), ts_start=0.0, ts_end=0.0, is_synthetic=False,
                      notes=(f"EXTERNAL server-everything sse; baseline_rss_mb={base:.2f}; "
                             f"attack_present={'no' if no_attack else 'yes'}"))

    out = {}
    for arm, na in (("baseline", True), ("attack", False)):
        recs = []
        for i in range(REPS + WARMUP):
            r = one(na)
            print(f"[v6_slow_sse/{arm}] {'warmup' if i < WARMUP else f'rep {i-WARMUP}'} "
                  f"rss={r.peak_rss_mb} cpu={r.mean_cpu_pct} p95={r.lat_p95_ms} err={r.error_rate}", flush=True)
            if i >= WARMUP:
                recs.append(r)
            time.sleep(1.0)
        out[arm] = recs
    return out


def run_v7_redos():
    """ReDoS (CWE-1333) against server-everything's resource-template matching
    (the CVE-2026-0621 UriTemplate surface). Baseline reads a normal resourceId;
    attack reads a long pathological id. SDK 1.30.0 is PATCHED, so we expect NO
    reproduction -- a clean 'patch holds on a third-party server' result."""
    import httpx
    port = 8907; url = f"http://127.0.0.1:{port}"
    PATHO = "a" * 50000  # long id to stress UriTemplate regex matching

    def one(no_attack):
        env = dict(os.environ, PORT=str(port))
        proc = subprocess.Popen([NODE, EXT_INDEX, "streamableHttp"], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not _port_open("127.0.0.1", port):
            if proc.poll() is not None:
                raise RuntimeError("v7 server exited before listen")
            time.sleep(0.1)
        sampler = make_sampler(proc.pid)
        try:
            sampler.start(); time.sleep(1.0)
            base = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0
            c = httpx.Client(timeout=15.0)
            h = {"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"}
            r = c.post(f"{url}/mcp", headers=h, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "v7", "version": "1.0"}}})
            sid = r.headers.get("mcp-session-id")
            if sid:
                h["mcp-session-id"] = sid
            c.post(f"{url}/mcp", headers=h, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            rid = "1" if no_attack else PATHO
            uri = f"demo://resource/dynamic/text/{rid}"
            lat = []; err = 0
            for i in range(8):  # a small burst
                t0 = time.perf_counter()
                try:
                    rr = c.post(f"{url}/mcp", headers=h, json={
                        "jsonrpc": "2.0", "id": 10 + i, "method": "resources/read",
                        "params": {"uri": uri}})
                    lat.append((time.perf_counter() - t0) * 1000)
                    if rr.status_code != 200:
                        err += 1
                except Exception:
                    lat.append((time.perf_counter() - t0) * 1000); err += 1
            c.close()
            wait_for_recovery(proc.pid, base)
            peak = sampler.series.peak_rss_mb; cpu = sampler.series.mean_cpu_pct
        finally:
            sampler.stop(); kill_tree(proc.pid); time.sleep(0.3)
        p50, p95, p99 = percentiles(lat)
        return Record(vector="v7_redos", transport="http", sdk="server-everything",
                      load_level=4, concurrency=1, mitigation=False,
                      peak_rss_mb=round(peak, 2), mean_cpu_pct=round(cpu, 2),
                      lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
                      error_rate=round(err / max(1, len(lat)), 3), ts_start=0.0, ts_end=0.0,
                      is_synthetic=False,
                      notes=(f"EXTERNAL server-everything redos(resource-template); "
                             f"baseline_rss_mb={base:.2f}; attack_present={'no' if no_attack else 'yes'}"))

    out = {}
    for arm, na in (("baseline", True), ("attack", False)):
        recs = []
        for i in range(REPS + WARMUP):
            r = one(na)
            print(f"[v7_redos/{arm}] {'warmup' if i < WARMUP else f'rep {i-WARMUP}'} "
                  f"rss={r.peak_rss_mb} cpu={r.mean_cpu_pct} p95={r.lat_p95_ms} err={r.error_rate}", flush=True)
            if i >= WARMUP:
                recs.append(r)
            time.sleep(1.0)
        out[arm] = recs
    return out


def summarize(name, channel, base, att):
    prim = "peak_rss_mb" if channel == "rss" else "mean_cpu_pct"
    b_prim = [getattr(r, prim) if hasattr(r, prim) else r[prim] for r in base]
    a_prim = [getattr(r, prim) if hasattr(r, prim) else r[prim] for r in att]
    g = lambda r, k: getattr(r, k) if hasattr(r, k) else r[k]
    b_p95 = [g(r, "lat_p95_ms") for r in base]; a_p95 = [g(r, "lat_p95_ms") for r in att]
    b_err = stats.mean_sd_ci([g(r, "error_rate") for r in base])["mean"]
    a_err = stats.mean_sd_ci([g(r, "error_rate") for r in att])["mean"]
    mwu = stats.mann_whitney_u(b_prim, a_prim)
    bm = statistics.median(b_prim); am = statistics.median(a_prim)
    p = mwu["p_value"]
    ratio = (am / bm) if bm else float("inf")
    reproduces = (p is not None and p < 0.05 and am > bm and (am - bm) >= max(3.0, 0.15 * bm)) \
        or (a_err - b_err) >= 0.10 \
        or (stats.median_iqr(a_p95)["median"] or 0) >= 2.0 * (stats.median_iqr(b_p95)["median"] or 1e9)
    return dict(
        channel=channel, prim=prim,
        base_prim=f"{stats.mean_sd_ci(b_prim)['mean']:.1f}",
        att_prim=f"{stats.mean_sd_ci(a_prim)['mean']:.1f}",
        base_p95=stats.fmt_median_iqr(stats.median_iqr(b_p95)),
        att_p95=stats.fmt_median_iqr(stats.median_iqr(a_p95)),
        base_err=f"{b_err:.2f}", att_err=f"{a_err:.2f}",
        mwu_p=f"{p:.4f}" if p is not None else "n/a",
        ratio=f"{ratio:.2f}x" if ratio != float('inf') else "n/a",
        reproduces=bool(reproduces))


def main():
    os.makedirs(OUT, exist_ok=True)
    results = {}
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    for name, cfg in HTTP_VECTORS.items():
        if only and name not in only:
            continue
        print(f"\n===== EXTERNAL {name} (server-everything, streamableHttp) =====", flush=True)
        base = run_http_arm(name, cfg, no_attack=True)
        att = run_http_arm(name, cfg, no_attack=False)
        json.dump([r.to_dict() for r in base + att],
                  open(os.path.join(OUT, f"{name}__external.json"), "w"), indent=2)
        results[name] = summarize(name, cfg["channel"], base, att)
    if not only or "v3_unbounded_stdio" in only:
        print(f"\n===== EXTERNAL v3_unbounded_stdio (server-everything, stdio) =====", flush=True)
        d = run_v3_stdio()
        json.dump([r.to_dict() for r in d["baseline"] + d["attack"]],
                  open(os.path.join(OUT, "v3_unbounded_stdio__external.json"), "w"), indent=2)
        results["v3_unbounded_stdio"] = summarize("v3_unbounded_stdio", "rss", d["baseline"], d["attack"])
    if not only or "v6_slow_sse" in only:
        print(f"\n===== EXTERNAL v6_slow_sse (server-everything, sse) =====", flush=True)
        d = run_v6_sse()
        json.dump([r.to_dict() for r in d["baseline"] + d["attack"]],
                  open(os.path.join(OUT, "v6_slow_sse__external.json"), "w"), indent=2)
        results["v6_slow_sse"] = summarize("v6_slow_sse", "rss", d["baseline"], d["attack"])
    if not only or "v7_redos" in only:
        print(f"\n===== EXTERNAL v7_redos (server-everything, resource-template ReDoS) =====", flush=True)
        d = run_v7_redos()
        json.dump([r.to_dict() for r in d["baseline"] + d["attack"]],
                  open(os.path.join(OUT, "v7_redos__external.json"), "w"), indent=2)
        results["v7_redos"] = summarize("v7_redos", "cpu", d["baseline"], d["attack"])

    print("\n\n### External-target results (server-everything, NOT authored by us)\n")
    print("| Vector | Channel | Baseline (no-attack) | Under attack | Ratio | MWU p | Benign p95 base->attack | Err base->attack | Weakness reproduces? |")
    print("|---|---|---|---|---|---|---|---|---|")
    order = ["v1_oversized_body", "v2_init_flood", "v3_unbounded_stdio", "v4_deep_json",
             "v5_tool_flood", "v6_slow_sse", "v7_redos"]
    n_rep = 0; n_tot = 0
    for name in order:
        if name not in results:
            continue
        s = results[name]; n_tot += 1
        if s["reproduces"]:
            n_rep += 1
        unit = "MB" if s["channel"] == "rss" else "% CPU"
        print(f"| {name} | {s['channel']} | {s['base_prim']} {unit} | {s['att_prim']} {unit} | "
              f"{s['ratio']} | {s['mwu_p']} | {s['base_p95']} -> {s['att_p95']} | "
              f"{s['base_err']} -> {s['att_err']} | {'**YES**' if s['reproduces'] else 'no'} |")
    print(f"\n**Weakness reproduces on the third-party server for {n_rep} of {n_tot} vectors tested.**")


if __name__ == "__main__":
    main()
