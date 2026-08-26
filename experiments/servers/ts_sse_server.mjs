// TypeScript-SDK reference server (legacy SSE transport), vector 6:
// Slow-SSE / slow read (CWE-400).
//
// REAL @modelcontextprotocol/sdk package, McpServer + SSEServerTransport.
// Note: SSEServerTransport.send() (dist/esm/server/sse.js) just calls
// `this._sseResponse.write(...)` -- it does NOT check the write() return
// value or wait for a 'drain' event. That is genuine, unmodified SDK
// behaviour, not something we injected: a slow/non-draining reader makes
// Node buffer every subsequent `write()` in-process without bound. This
// server's mitigation is the "corresponding control" this project adds
// on top: an outbound-buffer cap using Node's own
// `res.writableLength` (bytes queued but not yet flushed to the OS
// socket) -- if a connection's queue exceeds the cap, the connection is
// forcibly closed rather than keeping the data.
//
// On accepting a GET /sse connection, immediately starts pushing
// `push_mb` megabytes of notification traffic (as this reference server's
// stand-in for "the server has legitimate data to stream to this
// client") in fixed-size chunks, which is exactly the situation a slow
// reader can turn into unbounded server memory growth.

import http from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";

const PORT = parseInt(process.argv[2] || "8817", 10);
const HOST = "127.0.0.1";

const MIT_MAX_BUFFERED_BYTES = parseInt(process.env.MIT_SSE_MAX_BUFFERED_BYTES || "0", 10);
const PUSH_MB = parseFloat(process.env.PUSH_MB || "10");
const CHUNK_BYTES = 8 * 1024;

const sessions = new Map();

function makeServer() {
  const server = new McpServer({ name: "dos-research-reference-server-ts-sse", version: "1.0.0" });
  server.registerTool(
    "echo",
    { description: "benign tool", inputSchema: { text: z.string() } },
    async ({ text }) => ({ content: [{ type: "text", text }] })
  );
  return server;
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(chunks.length ? Buffer.concat(chunks) : undefined));
  });
}

async function pushBurst(res, transport) {
  const chunk = "X".repeat(CHUNK_BYTES);
  const totalBytes = Math.floor(PUSH_MB * 1024 * 1024);
  let sent = 0;
  while (sent < totalBytes) {
    if (res.destroyed || res.writableEnded) break;
    if (MIT_MAX_BUFFERED_BYTES > 0 && res.writableLength > MIT_MAX_BUFFERED_BYTES) {
      // mitigation: this connection is not draining fast enough -- stop
      // holding data for it and close it, rather than keep buffering.
      res.destroy();
      break;
    }
    await transport.send({ jsonrpc: "2.0", method: "notifications/message",
                            params: { level: "info", data: chunk } });
    sent += chunk.length;
    await new Promise((r) => setImmediate(r));
  }
}

const httpServer = http.createServer(async (req, res) => {
  if (req.url.startsWith("/sse") && req.method === "GET") {
    const transport = new SSEServerTransport("/messages", res);
    const server = makeServer();
    sessions.set(transport.sessionId, transport);
    await server.connect(transport);
    pushBurst(res, transport).catch(() => {});
    return;
  }
  if (req.url.startsWith("/messages") && req.method === "POST") {
    const url = new URL(req.url, `http://${HOST}`);
    const sid = url.searchParams.get("sessionId");
    const transport = sessions.get(sid);
    if (!transport) { res.writeHead(404).end(); return; }
    const body = await readBody(req);
    await transport.handlePostMessage(req, res, body ? JSON.parse(body.toString("utf-8")) : undefined);
    return;
  }
  res.writeHead(404).end();
});

httpServer.listen(PORT, HOST, () => {
  process.stderr.write(`READY pid=${process.pid} host=${HOST} port=${PORT}\n`);
});
