// TypeScript-SDK reference server (stdio transport), vector 3: Unbounded
// stdio stream (CWE-770).
//
// This is the REAL official @modelcontextprotocol/sdk package (npm
// "@modelcontextprotocol/sdk", modelcontextprotocol/typescript-sdk),
// using McpServer + StdioServerTransport.
//
// The mitigation here is NOT hand-rolled -- it is the SDK's OWN built-in
// `maxBufferSize` option on StdioServerTransport ("Maximum size of the
// read buffer in bytes. If a single message exceeds this size the
// transport will emit an error and close.", default 10 MB). We just
// choose the cap via env var:
//   MIT_STDIO_MAX_BUFFER_BYTES=0   -> mitigation OFF: cap set very high
//                                      (512 MB) so our (bounded, modest)
//                                      attack payload is never rejected
//   MIT_STDIO_MAX_BUFFER_BYTES=N   -> mitigation ON: cap set to N bytes
//
// READY marker + all diagnostics go to stderr; stdout is reserved for
// JSON-RPC framing.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const mitCap = parseInt(process.env.MIT_STDIO_MAX_BUFFER_BYTES || "0", 10);
const maxBufferSize = mitCap > 0 ? mitCap : 512 * 1024 * 1024; // 512 MB "off" ceiling

const server = new McpServer({ name: "dos-research-reference-server-ts-stdio", version: "1.0.0" });

server.registerTool(
  "echo",
  { description: "Trivial benign tool used to measure legitimate-client latency.",
    inputSchema: { text: z.string() } },
  async ({ text }) => ({ content: [{ type: "text", text }] })
);

const transport = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize });

process.stderr.write(`READY pid=${process.pid} maxBufferSize=${maxBufferSize}\n`);

await server.connect(transport);
