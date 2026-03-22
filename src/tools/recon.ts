/**
 * Reconnaissance tools.
 *
 * Quick recon, DNS enumeration, vhost brute-forcing, TLS SANs,
 * directory brute-force, git secret search, S3 bucket testing.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, runShell, requireTool, parseLines } from "../runner.js";
import * as fs from "node:fs";
import * as path from "node:path";

export function register(server: McpServer): void {
  server.tool(
    "recon_quick",
    "Quick reconnaissance: robots.txt, security.txt, common dirs, response headers. Returns robots_txt, security_txt, response_headers, accessible_directories, and error_page_snippet. Read-only, sends ~10 GET requests.",
    {
      target: z
        .string()
        .describe("Target domain or URL, e.g. example.com or https://example.com"),
    },
    async ({ target }) => {
      requireTool("curl");

      // Normalize target
      const base = (target.startsWith("http") ? target : `https://${target}`).replace(/\/$/, "");

      // robots.txt
      const robots = await runCmd("curl", ["-sk", "-m", "10", `${base}/robots.txt`]);

      // security.txt
      const security = await runCmd("curl", ["-sk", "-m", "10", `${base}/.well-known/security.txt`]);

      // Response headers
      const headers = await runCmd("curl", [
        "-sk", "-D", "-", "-o", "/dev/null", "-m", "10", base,
      ]);

      // Common directories
      const commonDirs = [
        "/admin/", "/login/", "/api/", "/dashboard/",
        "/wp-admin/", "/.git/", "/.env", "/backup/",
        "/config/", "/images/", "/uploads/", "/swagger/",
      ];
      const dirResults: Array<{ path: string; status: number }> = [];
      for (const d of commonDirs) {
        const res = await runCmd("curl", [
          "-sk", "-o", "/dev/null", "-w", "%{http_code}",
          "-m", "5", `${base}${d}`,
        ]);
        const status = /^\d+$/.test(res.stdout) ? parseInt(res.stdout, 10) : 0;
        if (status !== 404) {
          dirResults.push({ path: d, status });
        }
      }

      // 404 page analysis
      const errorPage = await runCmd("curl", ["-sk", "-m", "10", `${base}/nonexistent_path_12345`]);

      const result = {
        robots_txt:
          robots.success && robots.stdout.includes("User-agent")
            ? robots.stdout.slice(0, 2000)
            : "Not found or empty",
        security_txt:
          security.success && security.stdout.length > 10
            ? security.stdout.slice(0, 2000)
            : "Not found or empty",
        response_headers: headers.stdout.slice(0, 2000),
        accessible_directories: dirResults,
        error_page_snippet: errorPage.stdout.slice(0, 1000),
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "recon_dns",
    "Full DNS enumeration: A, AAAA, MX, TXT, NS, CNAME, AXFR, BIND version. Returns records object, axfr_result, and bind_version. Read-only DNS queries.",
    {
      target: z.string().describe("Target domain, e.g. example.com"),
    },
    async ({ target }) => {
      requireTool("dig");

      const recordTypes = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"];
      const records: Record<string, string[]> = {};
      for (const rtype of recordTypes) {
        const res = await runCmd("dig", ["+short", rtype, target]);
        records[rtype] = parseLines(res.stdout);
      }

      // Zone transfer attempt
      const nsServers = records["NS"] ?? [];
      let axfrResult = "";
      for (const ns of nsServers.slice(0, 3)) {
        const nsClean = ns.replace(/\.$/, "");
        const axfr = await runCmd("dig", ["AXFR", target, `@${nsClean}`], { timeout: 15 });
        if (axfr.success && axfr.stdout.length > 100) {
          axfrResult = axfr.stdout.slice(0, 3000);
          break;
        }
      }

      // BIND version disclosure
      let bindVersion = "";
      for (const ns of nsServers.slice(0, 2)) {
        const nsClean = ns.replace(/\.$/, "");
        const bv = await runCmd("dig", ["version.bind", "CHAOS", "TXT", `@${nsClean}`], { timeout: 10 });
        if (bv.success && bv.stdout.toLowerCase().includes("version")) {
          bindVersion = bv.stdout.slice(0, 500);
          break;
        }
      }

      const result = {
        records,
        axfr_result: axfrResult || "Zone transfer denied or no NS servers found.",
        bind_version: bindVersion || "Not disclosed.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "recon_vhost",
    "Brute-force virtual hosts by fuzzing the Host header. Returns baseline_length, results (vhost/status/length/length_delta), unique_vhosts, and tested count. Read-only, sends one request per wordlist entry.",
    {
      target: z
        .string()
        .describe("Target IP or domain to send requests to"),
      base_domain: z
        .string()
        .describe("Base domain for vhost names, e.g. hackycorp.com"),
      wordlist: z
        .string()
        .optional()
        .describe("Path to wordlist file. Uses built-in common subdomains if not provided."),
    },
    async ({ target, base_domain, wordlist }) => {
      requireTool("curl");

      // Built-in common subdomains
      const defaultSubs = [
        "admin", "www", "mail", "ftp", "api", "dev", "staging",
        "test", "portal", "dashboard", "app", "blog", "shop",
        "internal", "intranet", "vpn", "remote", "beta", "demo",
        "docs", "wiki", "git", "jenkins", "ci", "cd", "monitor",
        "grafana", "kibana", "elastic", "balancer", "proxy",
      ];

      let subs: string[];
      if (wordlist && fs.existsSync(wordlist)) {
        const content = fs.readFileSync(wordlist, "utf-8");
        subs = content
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.length > 0)
          .slice(0, 500);
      } else {
        subs = defaultSubs;
      }

      // Baseline: request with the raw target as Host
      const baseline = await runCmd("curl", [
        "-sk", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}",
        `http://${target}/`,
      ]);
      const bp = baseline.stdout.split(":");
      const baselineLength = bp.length > 1 ? parseInt(bp[1], 10) : 0;

      const results: Array<{
        vhost: string;
        status: number;
        length: number;
        length_delta: number;
      }> = [];

      for (const sub of subs) {
        const vhost = `${sub}.${base_domain}`;
        const res = await runCmd("curl", [
          "-sk", "-o", "/dev/null",
          "-w", "%{http_code}:%{size_download}",
          "-H", `Host: ${vhost}`,
          `http://${target}/`,
        ]);
        const parts = res.stdout.split(":");
        const status = parts.length > 0 ? parseInt(parts[0], 10) : 0;
        const length = parts.length > 1 ? parseInt(parts[1], 10) : 0;

        // Only include results different from baseline
        if (Math.abs(length - baselineLength) > 20 || (status !== 0 && status !== 301 && status !== 404)) {
          results.push({
            vhost,
            status,
            length,
            length_delta: length - baselineLength,
          });
        }
      }

      const result = {
        baseline_length: baselineLength,
        results,
        unique_vhosts: results.map((r) => r.vhost),
        tested: subs.length,
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "recon_tls_sans",
    "Extract Subject Alternative Names from the TLS certificate. Returns common_name, subject_alternative_names, issuer, validity, and san_count. Read-only TLS handshake.",
    {
      target: z
        .string()
        .describe("Target domain or IP:port, e.g. example.com or 1.2.3.4:443"),
    },
    async ({ target }) => {
      const host = target.includes(":") ? target.split(":")[0] : target;
      const port = target.includes(":") ? target.split(":")[1] : "443";

      const certInfo = await runShell(
        `echo | openssl s_client -servername ${host} -connect ${host}:${port} 2>/dev/null | openssl x509 -noout -text 2>/dev/null`
      );

      // Parse SANs
      const sans: string[] = [];
      let cn = "";
      let issuer = "";
      let validity = "";

      for (const rawLine of certInfo.stdout.split("\n")) {
        const line = rawLine.trim();
        if (line.includes("DNS:")) {
          for (const part of line.split(",")) {
            const p = part.trim();
            if (p.startsWith("DNS:")) {
              sans.push(p.slice(4));
            }
          }
        }
        if (line.includes("Subject:") && line.includes("CN")) {
          const cnStart = line.indexOf("CN");
          if (cnStart !== -1) {
            cn = line.slice(cnStart).split(",")[0].replace("CN = ", "").replace("CN=", "");
          }
        }
        if (line.includes("Issuer:")) {
          issuer = line.replace("Issuer:", "").trim();
        }
        if (line.includes("Not After")) {
          validity = line.trim();
        }
      }

      const result = {
        common_name: cn,
        subject_alternative_names: sans,
        issuer: issuer.slice(0, 200),
        validity,
        san_count: sans.length,
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "recon_directory_bruteforce",
    "Directory brute-force using parallel curl requests. Returns results (path/status/length), found_count, and paths_tested. Read-only GET requests, sends one request per wordlist entry per extension.",
    {
      target: z.string().describe("Base URL, e.g. https://example.com"),
      wordlist: z
        .string()
        .optional()
        .describe("Path to wordlist file. Uses built-in common paths if not provided."),
      threads: z
        .number()
        .min(1)
        .max(50)
        .describe("Concurrent request count")
        .default(10),
      extensions: z
        .string()
        .optional()
        .describe("Comma-separated extensions to append, e.g. 'php,html,txt'"),
    },
    async ({ target, wordlist, threads, extensions }) => {
      requireTool("curl");

      const base = target.replace(/\/$/, "");

      const defaultPaths = [
        "admin", "login", "api", "dashboard", "config", "backup",
        "uploads", "images", "css", "js", "fonts", "media",
        ".git", ".env", ".htaccess", "wp-admin", "wp-login.php",
        "robots.txt", "sitemap.xml", "swagger", "api-docs",
        "graphql", "health", "status", "metrics", "debug",
        "phpinfo.php", "info.php", "test", "temp", "tmp",
        "old", "bak", "archive", "data", "db", "database",
        "console", "panel", "manager", "administrator",
        "user", "users", "account", "accounts", "profile",
        "settings", "docs", "documentation", "help",
        "search", "download", "file", "files", "upload",
        "static", "assets", "public", "private", "secret",
        "hidden", "internal", "server-status", "server-info",
      ];

      let paths: string[];
      if (wordlist && fs.existsSync(wordlist)) {
        const content = fs.readFileSync(wordlist, "utf-8");
        paths = content
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.length > 0)
          .slice(0, 2000);
      } else {
        paths = defaultPaths;
      }

      // Expand with extensions
      const extList = extensions ? extensions.split(",") : [];
      const expandedPaths = [...paths];
      for (const ext of extList) {
        const cleanExt = ext.trim().replace(/^\./, "");
        for (const p of paths) {
          expandedPaths.push(`${p}.${cleanExt}`);
        }
      }

      async function checkPath(p: string): Promise<{ path: string; status: number; length: number } | null> {
        const res = await runCmd("curl", [
          "-sk", "-o", "/dev/null",
          "-w", "%{http_code}:%{size_download}",
          "-m", "5",
          `${base}/${p}`,
        ]);
        const parts = res.stdout.split(":");
        const status = parts.length > 0 ? parseInt(parts[0], 10) : 0;
        const length = parts.length > 1 ? parseInt(parts[1], 10) : 0;
        if (status !== 0 && status !== 404) {
          return { path: `/${p}`, status, length };
        }
        return null;
      }

      // Run in batches
      const results: Array<{ path: string; status: number; length: number }> = [];
      for (let i = 0; i < expandedPaths.length; i += threads) {
        const batch = expandedPaths.slice(i, i + threads);
        const batchResults = await Promise.all(batch.map(checkPath));
        for (const r of batchResults) {
          if (r !== null) results.push(r);
        }
      }

      const result = {
        results,
        found_count: results.length,
        paths_tested: expandedPaths.length,
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "recon_git_secrets",
    "Search git history for secrets: commit messages, author info, branches, deleted files. Returns secrets_in_code_history, unique_authors, branches, deleted_files_summary, and suspicious_commit_messages. Read-only git operations on local repository.",
    {
      repo_path: z.string().describe("Path to the git repository"),
    },
    async ({ repo_path }) => {
      requireTool("git");

      const repo = path.resolve(repo_path);
      if (!fs.existsSync(path.join(repo, ".git"))) {
        const result = { error: `Not a git repository: ${repo}` };
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      // Search commit content for secrets
      const secretPatterns = [
        "password", "secret", "api_key", "apikey", "token",
        "private_key", "aws_access", "aws_secret",
      ];
      const secretHits: string[] = [];
      for (const pattern of secretPatterns) {
        const res = await runCmd(
          "git",
          ["-C", repo, "log", "--all", "-S", pattern, "--oneline"],
          { timeout: 30 }
        );
        if (res.stdout) {
          for (const line of parseLines(res.stdout).slice(0, 5)) {
            secretHits.push(`[${pattern}] ${line}`);
          }
        }
      }

      // Author enumeration
      const authors = await runCmd(
        "git",
        ["-C", repo, "log", "--format=%an <%ae>", "--all"],
        { timeout: 15 }
      );
      const uniqueAuthors = [...new Set(parseLines(authors.stdout))];

      // All branches
      const branches = await runCmd(
        "git",
        ["-C", repo, "branch", "-a"],
        { timeout: 10 }
      );

      // Deleted files
      const deleted = await runCmd(
        "git",
        ["-C", repo, "log", "--diff-filter=D", "--summary", "--all", "--oneline"],
        { timeout: 30 }
      );

      // Commit messages with keywords
      const msgHits = await runShell(
        `git -C '${repo}' log --all --oneline 2>/dev/null | grep -iE 'key|secret|password|credential|token|fix.*leak' | head -20`
      );

      const result = {
        secrets_in_code_history: secretHits.slice(0, 50),
        unique_authors: uniqueAuthors.slice(0, 30),
        branches: parseLines(branches.stdout).slice(0, 30),
        deleted_files_summary: parseLines(deleted.stdout).slice(0, 30),
        suspicious_commit_messages: parseLines(msgHits.stdout).slice(0, 20),
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "recon_s3_bucket",
    "Test an S3 bucket for public access (listing, reading). Returns bucket_url, listable, listing_snippet, and readable_files. Read-only requests to S3.",
    {
      bucket_name: z
        .string()
        .describe("S3 bucket name to test, e.g. 'assets.example.com'"),
    },
    async ({ bucket_name }) => {
      requireTool("curl");

      const bucketUrl = `https://${bucket_name}.s3.amazonaws.com`;

      // Test bucket listing
      const listing = await runCmd("curl", ["-sk", "-m", "10", `${bucketUrl}/`]);
      const listable =
        listing.stdout.includes("<ListBucketResult") ||
        listing.stdout.includes("<Contents>");

      // Try common sensitive files
      const sensitiveFiles = [
        "key.txt", "credentials.txt", "config.json", ".env",
        "backup.sql", "database.sql", "id_rsa", "secret.txt",
      ];
      const readable: string[] = [];
      for (const f of sensitiveFiles) {
        const res = await runCmd("curl", [
          "-sk", "-o", "/dev/null", "-w", "%{http_code}",
          "-m", "5",
          `${bucketUrl}/${f}`,
        ]);
        const status = /^\d+$/.test(res.stdout) ? parseInt(res.stdout, 10) : 0;
        if (status === 200) {
          readable.push(f);
        }
      }

      const result = {
        bucket_url: bucketUrl,
        listable,
        listing_snippet: listable ? listing.stdout.slice(0, 2000) : "",
        readable_files: readable,
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );
}
