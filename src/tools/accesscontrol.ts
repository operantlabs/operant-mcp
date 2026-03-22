/**
 * Access Control testing tools.
 *
 * Tests IDOR via ID enumeration and role escalation via cookie/parameter manipulation.
 * Based on PortSwigger Access Control labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "idor_test",
    "Test Insecure Direct Object References by iterating through IDs/GUIDs.\n\nSends requests with each ID and compares response status codes and lengths. Differing responses suggest IDOR — the server returns data for other users' objects without proper authorization checks.\n\nReturns: {\"baseline\": dict, \"results\": [{\"id\": str, \"status\": int, \"length\": int, \"different\": bool, \"snippet\": str}], \"idor_candidates\": [str]}.\n\nSide effects: Read-only requests. Sends len(id_list) + 1 requests.\n\nErrors: ConnectionError if target unreachable.",
    {
      url: z
        .string()
        .describe(
          "URL with ID parameter, e.g. https://target/my-account?id=123 or https://target/api/users/123"
        ),
      parameter: z
        .string()
        .describe(
          "Parameter name containing the ID, e.g. 'id'. Use '__path__' if the ID is in the URL path"
        ),
      id_list: z
        .array(z.string())
        .min(1)
        .max(50)
        .describe(
          "List of IDs/GUIDs to test, e.g. ['1','2','3'] or ['abc-def-123', 'ghi-jkl-456']"
        ),
      auth_cookie: z
        .string()
        .optional()
        .describe(
          "Session cookie to send (e.g. 'session=abc123'). If None, tests without auth"
        ),
      method: z
        .string()
        .describe("HTTP method to use")
        .optional(),
    },
    async ({ url, parameter, id_list, auth_cookie, method = "GET" }) => {
      requireTool("curl");

      // Baseline: request with an obviously-invalid ID
      function buildUrl(testId: string): string {
        if (parameter === "__path__") {
          // ID is the last path segment — replace it (replicates Python's rsplit("/", 1))
          const lastSlash = url.lastIndexOf("/");
          if (lastSlash !== -1) {
            return `${url.slice(0, lastSlash)}/${testId}`;
          }
          return `${url}/${testId}`;
        } else {
          const base = url.split("?")[0];
          return `${base}?${parameter}=${testId}`;
        }
      }

      const invalidUrl = buildUrl("99999999-invalid-0000-0000-000000000000");
      const baselineArgs = [
        "-sk",
        "-o",
        "-",
        "-w",
        "\n__META__%{http_code}:%{size_download}",
        "-X",
        method,
      ];
      if (auth_cookie) {
        baselineArgs.push("-b", auth_cookie);
      }
      baselineArgs.push(invalidUrl);

      const baselineRes = await runCmd("curl", baselineArgs);
      let baseBody = baselineRes.stdout;
      const baseMetaMarker = baseBody.lastIndexOf("__META__");
      let baseStatus = 0;
      let baseLength = 0;
      if (baseMetaMarker !== -1) {
        const meta = baseBody.slice(baseMetaMarker + 8).trim();
        const parts = meta.split(":");
        baseStatus = parts[0] ? parseInt(parts[0], 10) : 0;
        baseLength = parts[1] ? parseInt(parts[1], 10) : 0;
      }

      const results: Array<{
        id: string;
        status: number;
        length: number;
        different_from_baseline: boolean;
        response_snippet: string;
      }> = [];
      const idorCandidates: string[] = [];

      for (const testId of id_list) {
        const targetUrl = buildUrl(testId);
        const curlArgs = [
          "-sk",
          "-o",
          "-",
          "-w",
          "\n__META__%{http_code}:%{size_download}",
          "-X",
          method,
        ];
        if (auth_cookie) {
          curlArgs.push("-b", auth_cookie);
        }
        curlArgs.push(targetUrl);

        const res = await runCmd("curl", curlArgs);
        let resBody = res.stdout;
        const metaMarker = resBody.lastIndexOf("__META__");
        let status = 0;
        let length = 0;
        if (metaMarker !== -1) {
          const meta = resBody.slice(metaMarker + 8).trim();
          const parts = meta.split(":");
          status = parts[0] ? parseInt(parts[0], 10) : 0;
          length = parts[1] ? parseInt(parts[1], 10) : 0;
          resBody = resBody.slice(0, metaMarker);
        }

        const different =
          status !== baseStatus || Math.abs(length - baseLength) > 50;
        const entry = {
          id: testId,
          status,
          length,
          different_from_baseline: different,
          response_snippet: resBody.slice(0, 500),
        };
        results.push(entry);
        if (different && status === 200) {
          idorCandidates.push(testId);
        }
      }

      const result = {
        baseline: { status: baseStatus, length: baseLength },
        results,
        idor_candidates: idorCandidates,
        hint:
          idorCandidates.length > 0
            ? `${idorCandidates.length} ID(s) returned different data — potential IDOR.`
            : "All IDs returned consistent responses. IDOR unlikely on this endpoint.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );

  server.tool(
    "role_escalation_test",
    "Test cookie/parameter-based role escalation.\n\nSends requests with various role cookie values (Admin=true, roleid=2, etc.) and checks for privilege escalation. Also tests JSON body field manipulation for profile update endpoints.\n\nReturns: {\"baseline\": dict, \"results\": [{\"value\": str, \"status\": int, \"length\": int, \"escalated\": bool}], \"escalation_candidates\": [str]}.\n\nSide effects: If json_body is set, sends POST/PUT requests that may modify state.",
    {
      url: z
        .string()
        .describe(
          "Protected URL to access, e.g. https://target/admin or https://target/api/users"
        ),
      cookie_name: z
        .string()
        .describe(
          "Cookie name for role control, e.g. 'admin', 'role', 'is_admin'"
        ),
      cookie_values: z
        .array(z.string())
        .min(1)
        .max(20)
        .describe(
          "Values to test, e.g. ['true','1','admin','2','yes']"
        ),
      extra_cookies: z
        .string()
        .optional()
        .describe(
          "Additional cookies to include, e.g. 'session=abc123; logged_in=true'"
        ),
      json_body: z
        .string()
        .optional()
        .describe(
          "JSON body for POST-based role escalation, e.g. '{\"roleid\":2}'. Will test each value substituted"
        ),
      json_field: z
        .string()
        .optional()
        .describe(
          "JSON field to manipulate in json_body, e.g. 'roleid'"
        ),
    },
    async ({
      url,
      cookie_name,
      cookie_values,
      extra_cookies,
      json_body,
      json_field,
    }) => {
      requireTool("curl");

      // Baseline without the role cookie
      const baselineArgs = [
        "-sk",
        "-o",
        "-",
        "-w",
        "\n__META__%{http_code}:%{size_download}",
      ];
      if (extra_cookies) {
        baselineArgs.push("-b", extra_cookies);
      }
      baselineArgs.push(url);

      const baselineRes = await runCmd("curl", baselineArgs);
      let baseBody = baselineRes.stdout;
      const baseMetaMarker = baseBody.lastIndexOf("__META__");
      let baseStatus = 0;
      let baseLength = 0;
      if (baseMetaMarker !== -1) {
        const meta = baseBody.slice(baseMetaMarker + 8).trim();
        const parts = meta.split(":");
        baseStatus = parts[0] ? parseInt(parts[0], 10) : 0;
        baseLength = parts[1] ? parseInt(parts[1], 10) : 0;
      }

      const results: Array<{
        cookie_value: string;
        status: number;
        length: number;
        escalated: boolean;
        response_snippet: string;
      }> = [];
      const escalationCandidates: string[] = [];

      for (const value of cookie_values) {
        let cookieStr = `${cookie_name}=${value}`;
        if (extra_cookies) {
          cookieStr = `${extra_cookies}; ${cookieStr}`;
        }

        let curlArgs: string[];
        if (json_body && json_field) {
          // POST/PUT with modified JSON body
          let modifiedBody = json_body;
          try {
            const bodyDict = JSON.parse(json_body);
            bodyDict[json_field] = value;
            modifiedBody = JSON.stringify(bodyDict);
          } catch {
            modifiedBody = json_body;
          }

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
            modifiedBody,
            "-b",
            cookieStr,
            url,
          ];
        } else {
          curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-b",
            cookieStr,
            url,
          ];
        }

        const res = await runCmd("curl", curlArgs);
        let resBody = res.stdout;
        const metaMarker = resBody.lastIndexOf("__META__");
        let status = 0;
        let length = 0;
        if (metaMarker !== -1) {
          const meta = resBody.slice(metaMarker + 8).trim();
          const parts = meta.split(":");
          status = parts[0] ? parseInt(parts[0], 10) : 0;
          length = parts[1] ? parseInt(parts[1], 10) : 0;
          resBody = resBody.slice(0, metaMarker);
        }

        const escalated =
          (status === 200 && [401, 403, 302].includes(baseStatus)) ||
          (Math.abs(length - baseLength) > 100 && status === 200);

        const entry = {
          cookie_value: value,
          status,
          length,
          escalated,
          response_snippet: resBody.slice(0, 500),
        };
        results.push(entry);
        if (escalated) {
          escalationCandidates.push(value);
        }
      }

      const result = {
        baseline: { status: baseStatus, length: baseLength },
        cookie_name,
        results,
        escalation_candidates: escalationCandidates,
        hint:
          escalationCandidates.length > 0
            ? `Role escalation possible with ${cookie_name}=${JSON.stringify(escalationCandidates)}`
            : "No escalation detected. Try different cookie names or values.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );
}
