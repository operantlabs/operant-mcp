#!/usr/bin/env node

/**
 * operant-mcp — Security testing MCP server
 *
 * 51 security testing tools across 19 modules + 8 methodology prompts.
 * Runs via stdio transport for use with any MCP client.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

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

// Start stdio transport
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
