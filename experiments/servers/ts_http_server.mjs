// TypeScript-SDK reference server (Streamable HTTP transport), used by
// vector 5 (tool-invocation flooding, CWE-400).
//
// REAL @modelcontextprotocol/sdk package, McpServer + StreamableHTTPServerTransport,
// on a plain node:http server. Since the raw (non-Express) SDK transport is
// per-session (one transport instance = one session -- confirmed by
// reading dist/esm/server/webStandardStreamableHttp.js), this file keeps a
// small session map itself, exactly the pattern the SDK's own docs show.
//
// Mitigation (env MIT_INVOCATION_RATE, tokens/window; MIT_INVOCATION_WINDOW_MS):
// a sliding-window rate limiter applied ONLY to "tools/call" requests,
// checked before the request ever reaches the SDK's dispatcher. Not part
// of the stock SDK -- this is the control this project contributes.
//
// Binds to 127.0.0.1 ONLY. Port from argv[2] (argv[0]=node, argv[1]=script).

import http from "node:http";
import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = parseInt(process.argv[2] || "8815", 10);
const HOST = "127.0.0.1";

const MIT_RATE = parseInt(process.env.MIT_INVOCATION_RATE || "0", 10);
const MIT_WINDOW_MS = parseInt(process.env.MIT_INVOCATION_WINDOW_MS || "1000", 10);

const sessions = new Map(); // sessionId -> transport
let invocationTimestamps = [];

function makeServer() {
  const server = new McpServer({ name: "dos-research-reference-server-ts-http", version: "1.0.0" });
  server.registerTool(
    "echo",
    { description: "Trivial benign tool used to measure legitimate-client latency.",
      inputSchema: { text: z.string() } },
    async ({ text }) => ({ content: [{ type: "text", text }] })
  );
  return server;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function invocationRateLimited() {
  if (MIT_RATE <= 0) return false;
  const now = Date.now();
  invocationTimestamps = invocationTimestamps.filter((t) => now - t < MIT_WINDOW_MS);
  if (invocationTimestamps.length >= MIT_RATE) return true;
  invocationTimestamps.push(now);
  return false;
}

const httpServer = http.createServer(async (req, res) => {
  if (req.url !== "/mcp") {
    res.writeHead(404).end();
    return;
  }
  try {
    const raw = await readBody(req);
    let parsed;
    try {
      parsed = raw.length ? JSON.parse(raw.toString("utf-8")) : undefined;
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid json" }));
      return;
    }

    if (parsed && parsed.method === "tools/call" && invocationRateLimited()) {
      res.writeHead(429, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "too many tool invocations", mitigation: "invocation_rate_limit" }));
      return;
    }

    const sessionId = req.headers["mcp-session-id"];
    let transport = sessionId ? sessions.get(sessionId) : undefined;

    if (!transport) {
      if (sessionId) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unknown session" }));
        return;
      }
      const server = makeServer();
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        onsessioninitialized: (sid) => sessions.set(sid, transport),
      });
      await server.connect(transport);
    }

    await transport.handleRequest(req, res, parsed);
  } catch (err) {
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(err) }));
    }
  }
});

httpServer.listen(PORT, HOST, () => {
  process.stderr.write(`READY pid=${process.pid} host=${HOST} port=${PORT}\n`);
});
