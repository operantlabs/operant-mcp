#!/usr/bin/env node

/**
 * operant-mcp — Security testing MCP server
 *
 * 51 security testing tools across 19 modules + 8 methodology prompts.
 * Supports both stdio and HTTP Streamable transports.
 *
 * Usage:
 *   npx operant-mcp          # stdio mode (default)
 *   PORT=3000 npx operant-mcp --http   # HTTP Streamable mode
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer as createHttpServer, IncomingMessage, ServerResponse } from "node:http";

// Tool modules
import { register as registerSqli } from "./tools/sqli.js";
import { register as registerXss } from "./tools/xss.js";
import { register as registerCmdi } from "./tools/cmdi.js";
import { register as registerTraversal } from "./tools/traversal.js";
import { register as registerSsrf } from "./tools/ssrf.js";
import { register as registerPcap } from "./tools/pcap.js";
import { register as registerRecon } from "./tools/recon.js";
import { register as registerMemory } from "./tools/memory.js";
import { register as registerMalware } from "./tools/malware.js";
import { register as registerCloud } from "./tools/cloud.js";
import { register as registerAuth } from "./tools/auth.js";
import { register as registerAccessControl } from "./tools/accesscontrol.js";
import { register as registerBizLogic } from "./tools/bizlogic.js";
import { register as registerClickjack } from "./tools/clickjack.js";
import { register as registerCors } from "./tools/cors.js";
import { register as registerFileUpload } from "./tools/fileupload.js";
import { register as registerNosqli } from "./tools/nosqli.js";
import { register as registerDeserialization } from "./tools/deserialization.js";
import { register as registerGraphql } from "./tools/graphql.js";

// Prompts
import { register as registerPrompts } from "./prompts.js";

// Resources
import { register as registerResources } from "./resources.js";

/** Create and configure an operant MCP server instance */
function createServer(): McpServer {
  const server = new McpServer({
    name: "operant",
    version: "1.0.0",
    description:
      "Security testing MCP server with 51 tools for penetration testing, " +
      "network forensics, memory analysis, and vulnerability assessment. " +
      "Tools require various CLI utilities (curl, tshark, volatility, etc.) " +
      "to be installed on the system.",
  });

  // Register all tool modules
  registerSqli(server);
  registerXss(server);
  registerCmdi(server);
  registerTraversal(server);
  registerSsrf(server);
  registerPcap(server);
  registerRecon(server);
  registerMemory(server);
  registerMalware(server);
  registerCloud(server);
  registerAuth(server);
  registerAccessControl(server);
  registerBizLogic(server);
  registerClickjack(server);
  registerCors(server);
  registerFileUpload(server);
  registerNosqli(server);
  registerDeserialization(server);
  registerGraphql(server);

  // Register methodology prompts
  registerPrompts(server);

  // Register reference resources
  registerResources(server);

  return server;
}

/**
 * Export createSandboxServer for Smithery registry scanning.
 * Returns a fresh server instance (not connected to any transport)
 * so Smithery can introspect tools/resources without conflicts.
 */
export function createSandboxServer() {
  return createServer();
}

// Start stdio transport (default)
async function startStdio() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Start HTTP Streamable transport
async function startHttp() {
  const port = parseInt(process.env.PORT || "3000", 10);

  const httpServer = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    // CORS headers for all requests
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, Mcp-Session-Id");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || "/", `http://localhost:${port}`);

    if (url.pathname === "/mcp") {
      // Create a new transport per session for stateless mode
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // stateless
      });
      const server = createServer();
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } else if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: "operant-mcp", version: "1.0.1" }));
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found. Use /mcp for MCP endpoint or /health for health check." }));
    }
  });

  httpServer.listen(port, () => {
    console.error(`operant-mcp HTTP server listening on port ${port}`);
    console.error(`MCP endpoint: http://localhost:${port}/mcp`);
  });
}

// Determine transport mode from CLI args
const useHttp = process.argv.includes("--http") || !!process.env.MCP_HTTP;
const startFn = useHttp ? startHttp : startStdio;

startFn().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
