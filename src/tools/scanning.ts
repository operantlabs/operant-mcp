/**
 * Scanning and fuzzing tools using nuclei, ffuf, and arjun.
 *
 * Wraps popular security scanning tools for template-based vulnerability
 * scanning, directory/parameter fuzzing, and hidden parameter discovery.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runShell } from "../runner.js";
import { randomUUID } from "node:crypto";
import { readFile, unlink } from "node:fs/promises";

const GO_BIN = `${process.env.HOME}/go/bin`;
const PATH_ENV = `${GO_BIN}:${process.env.PATH}`;

export function register(server: McpServer): void {
  server.tool(
    "nuclei_scan",
    "Run nuclei vulnerability scanner against a target. Supports template IDs, tags (cve, xss, sqli, etc.), and severity filtering. Returns array of findings in JSON format. Side effects: Sends multiple HTTP requests to target based on templates.",
    {
      target_url: z.string().describe("Target URL to scan, e.g. https://example.com"),
      templates: z.string().optional()
        .describe("Comma-separated template IDs or tags, e.g. 'cve,xss,sqli' or 'CVE-2021-44228'"),
      severity: z.string().optional()
        .describe("Comma-separated severity filter, e.g. 'critical,high,medium'"),
      rate_limit: z.number().optional()
        .describe("Max requests per second (default 150)"),
      extra_args: z.string().optional()
        .describe("Additional nuclei CLI arguments"),
    },
    async ({ target_url, templates, severity, rate_limit, extra_args }) => {
      const outputFile = `/tmp/nuclei-${randomUUID().slice(0, 8)}.json`;

      let cmd = `PATH=${PATH_ENV} nuclei -u ${JSON.stringify(target_url)} -json -silent -o ${outputFile}`;

      if (templates) {
        // Check if it looks like tags or template IDs
        if (templates.includes("/") || templates.endsWith(".yaml")) {
          cmd += ` -t ${JSON.stringify(templates)}`;
        } else {
          cmd += ` -tags ${JSON.stringify(templates)}`;
        }
      }

      if (severity) {
        cmd += ` -severity ${JSON.stringify(severity)}`;
      }

      if (rate_limit) {
        cmd += ` -rl ${rate_limit}`;
      }

      if (extra_args) {
        cmd += ` ${extra_args}`;
      }

      const res = await runShell(cmd, { timeout: 300 });

      let findings: any[] = [];
      try {
        const content = await readFile(outputFile, "utf-8");
        const lines = content.split("\n").filter((l) => l.trim());
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            findings.push({
              template_id: entry["template-id"] ?? entry.templateID ?? "",
              name: entry.info?.name ?? entry.name ?? "",
              severity: entry.info?.severity ?? entry.severity ?? "",
              matched_at: entry["matched-at"] ?? entry.matched ?? "",
              matcher_name: entry["matcher-name"] ?? "",
              description: entry.info?.description ?? "",
              reference: entry.info?.reference ?? [],
              curl_command: entry["curl-command"] ?? "",
            });
          } catch {
            // Skip malformed lines
          }
        }
      } catch {
        // Output file may not exist if no findings
      }

      await unlink(outputFile).catch(() => {});

      const result = {
        target: target_url,
        total_findings: findings.length,
        findings,
        command_stderr: res.stderr ? res.stderr.slice(0, 500) : undefined,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "ffuf_fuzz",
    "Directory and parameter fuzzing with ffuf. Target URL must contain 'FUZZ' keyword where the wordlist values are injected. Returns discovered paths/parameters with status codes and sizes.",
    {
      target_url: z.string().describe("Target URL with FUZZ keyword, e.g. https://example.com/FUZZ"),
      wordlist: z.string().optional()
        .describe("Wordlist path, or 'common' for built-in SecLists common.txt (default: common)"),
      method: z.enum(["GET", "POST"]).default("GET").describe("HTTP method"),
      match_codes: z.string().default("200,301,302,307,401,403")
        .describe("Comma-separated HTTP status codes to match"),
      filter_size: z.string().optional()
        .describe("Filter out responses of this size (comma-separated)"),
      headers: z.record(z.string()).optional()
        .describe("Additional headers as key-value pairs"),
      rate_limit: z.number().optional()
        .describe("Requests per second limit"),
      extra_args: z.string().optional()
        .describe("Additional ffuf CLI arguments"),
    },
    async ({ target_url, wordlist, method, match_codes, filter_size, headers, rate_limit, extra_args }) => {
      const outputFile = `/tmp/ffuf-${randomUUID().slice(0, 8)}.json`;

      // Resolve wordlist
      let wl = wordlist ?? "common";
      if (wl === "common") {
        // Try common SecLists locations
        const commonPaths = [
          "/usr/share/seclists/Discovery/Web-Content/common.txt",
          "/usr/share/wordlists/dirb/common.txt",
          "/opt/SecLists/Discovery/Web-Content/common.txt",
          `${process.env.HOME}/SecLists/Discovery/Web-Content/common.txt`,
          `${process.env.HOME}/wordlists/common.txt`,
        ];
        // We'll let ffuf fail if none exist — the error message will guide the user
        const checkRes = await runShell(
          `for f in ${commonPaths.map((p) => JSON.stringify(p)).join(" ")}; do [ -f "$f" ] && echo "$f" && break; done`,
          { timeout: 5 }
        );
        if (checkRes.stdout.trim()) {
          wl = checkRes.stdout.trim();
        } else {
          wl = "/usr/share/seclists/Discovery/Web-Content/common.txt";
        }
      }

      let cmd = `PATH=${PATH_ENV} ffuf -u ${JSON.stringify(target_url)} -w ${JSON.stringify(wl)} -mc ${JSON.stringify(match_codes)} -X ${method} -json -silent -o ${outputFile}`;

      if (filter_size) {
        cmd += ` -fs ${JSON.stringify(filter_size)}`;
      }

      if (headers) {
        for (const [k, v] of Object.entries(headers)) {
          cmd += ` -H ${JSON.stringify(`${k}: ${v}`)}`;
        }
      }

      if (rate_limit) {
        cmd += ` -rate ${rate_limit}`;
      }

      if (extra_args) {
        cmd += ` ${extra_args}`;
      }

      const res = await runShell(cmd, { timeout: 300 });

      let results: any[] = [];
      try {
        const content = await readFile(outputFile, "utf-8");
        const data = JSON.parse(content);
        const entries = data.results ?? [];
        results = entries.map((e: any) => ({
          input: e.input?.FUZZ ?? "",
          url: e.url ?? "",
          status: e.status ?? 0,
          length: e.length ?? 0,
          words: e.words ?? 0,
          lines: e.lines ?? 0,
          content_type: e["content-type"] ?? "",
          redirect_location: e.redirectlocation ?? "",
        }));
      } catch {
        // Try parsing as line-delimited JSON
        try {
          const content = await readFile(outputFile, "utf-8");
          const lines = content.split("\n").filter((l) => l.trim());
          for (const line of lines) {
            try {
              results.push(JSON.parse(line));
            } catch {
              // skip
            }
          }
        } catch {
          // No output file
        }
      }

      await unlink(outputFile).catch(() => {});

      const result = {
        target: target_url,
        wordlist: wl,
        total_discovered: results.length,
        results,
        command_stderr: res.stderr ? res.stderr.slice(0, 500) : undefined,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "param_discover",
    "Discover hidden parameters on a URL using arjun. Sends requests with parameter wordlists to detect reflected or functional parameters. Returns list of discovered parameter names.",
    {
      target_url: z.string().describe("Target URL to discover parameters on"),
      method: z.enum(["GET", "POST"]).default("GET").describe("HTTP method"),
      extra_args: z.string().optional().describe("Additional arjun CLI arguments"),
    },
    async ({ target_url, method, extra_args }) => {
      const outputFile = `/tmp/arjun-${randomUUID().slice(0, 8)}.json`;

      let cmd = `PATH=${PATH_ENV} arjun -u ${JSON.stringify(target_url)} -m ${method} -oJ ${outputFile}`;

      if (extra_args) {
        cmd += ` ${extra_args}`;
      }

      const res = await runShell(cmd, { timeout: 120 });

      let params: string[] = [];
      try {
        const content = await readFile(outputFile, "utf-8");
        const data = JSON.parse(content);
        // Arjun outputs { "url": [...params] }
        for (const url of Object.keys(data)) {
          const discovered = data[url];
          if (Array.isArray(discovered)) {
            params.push(...discovered);
          }
        }
      } catch {
        // Try extracting from stdout
        const match = res.stdout.match(/\[(.+)\]/);
        if (match) {
          try {
            params = JSON.parse(`[${match[1]}]`);
          } catch {
            // skip
          }
        }
      }

      await unlink(outputFile).catch(() => {});

      const result = {
        target: target_url,
        method,
        discovered_parameters: params,
        total_found: params.length,
        command_output: res.stdout ? res.stdout.slice(0, 500) : undefined,
        command_stderr: res.stderr ? res.stderr.slice(0, 500) : undefined,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
