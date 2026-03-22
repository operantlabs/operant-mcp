/**
 * Memory Forensics tools.
 *
 * Volatility 2 (Linux) and Volatility 3 (Windows) wrappers,
 * plus rootkit detection.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, parseLines } from "../runner.js";
import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";

export function register(server: McpServer): void {
  function validateDump(dumpPath: string): string {
    const abspath = path.resolve(dumpPath);
    if (!fs.existsSync(abspath) || !fs.statSync(abspath).isFile()) {
      throw new Error(`Memory dump not found: ${abspath}`);
    }
    return abspath;
  }

  function findVolatility2(): string | null {
    for (const name of ["vol.py", "volatility", "volatility2"]) {
      try {
        const result = execSync(`which ${name}`, { encoding: "utf-8" }).trim();
        if (result) return name;
      } catch {
        // not found, try next
      }
    }
    return null;
  }

  function findVolatility3(): string | null {
    for (const name of ["vol", "vol3", "volatility3"]) {
      try {
        const result = execSync(`which ${name}`, { encoding: "utf-8" }).trim();
        if (result) return name;
      } catch {
        // not found, try next
      }
    }
    return null;
  }

  server.tool(
    "volatility_linux",
    "Run a Volatility 2 Linux plugin against a memory dump. Returns plugin, profile, success, output, and errors. Read-only analysis. Requires volatility2 (vol.py) on PATH.",
    {
      dump_path: z.string().describe("Path to the Linux memory dump file"),
      profile: z
        .string()
        .describe("Volatility 2 profile name, e.g. 'LinuxCentOS7_7_1908x64'"),
      plugin: z
        .enum([
          "linux_banner",
          "linux_bash",
          "linux_pslist",
          "linux_pstree",
          "linux_netstat",
          "linux_enumerate_files",
          "linux_check_syscall",
          "linux_hidden_modules",
          "linux_lsmod",
          "linux_mount",
          "linux_ifconfig",
          "linux_route_cache",
        ])
        .describe("Volatility 2 Linux plugin to run"),
    },
    async ({ dump_path, profile, plugin }) => {
      const volBin = findVolatility2();
      if (!volBin) {
        const result = { error: "Volatility 2 not found. Install it and ensure vol.py is on PATH." };
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      const dump = validateDump(dump_path);

      const res = await runCmd(
        volBin,
        [`--profile=${profile}`, "-f", dump, plugin],
        { timeout: 300 }
      );

      const result = {
        plugin,
        profile,
        success: res.success,
        output: res.stdout.slice(0, 5000),
        errors: res.stderr ? res.stderr.slice(0, 1000) : "",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "volatility_windows",
    "Run a Volatility 3 Windows plugin against a memory dump. Returns plugin, success, output, and errors. Read-only analysis, Volatility 3 auto-detects OS. Requires vol3 (vol) on PATH.",
    {
      dump_path: z.string().describe("Path to the Windows memory dump file"),
      plugin: z
        .enum([
          "windows.info",
          "windows.pslist",
          "windows.pstree",
          "windows.netscan",
          "windows.netstat",
          "windows.filescan",
          "windows.malfind",
          "windows.cmdline",
          "windows.dlllist",
          "windows.handles",
          "windows.registry.hivelist",
          "windows.registry.printkey",
          "windows.envars",
          "windows.svcscan",
        ])
        .describe("Volatility 3 Windows plugin to run"),
    },
    async ({ dump_path, plugin }) => {
      const volBin = findVolatility3();
      if (!volBin) {
        const result = { error: "Volatility 3 not found. Install it and ensure 'vol' is on PATH." };
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      const dump = validateDump(dump_path);

      const res = await runCmd(
        volBin,
        ["-f", dump, plugin],
        { timeout: 300 }
      );

      const result = {
        plugin,
        success: res.success,
        output: res.stdout.slice(0, 5000),
        errors: res.stderr ? res.stderr.slice(0, 1000) : "",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "memory_detect_rootkit",
    "Check for rootkits via syscall table tampering and hidden kernel modules. Runs linux_check_syscall and linux_hidden_modules plugins. Returns syscall_check, hidden_modules, rootkit_indicators, and likely_compromised. Read-only analysis.",
    {
      dump_path: z.string().describe("Path to the Linux memory dump file"),
      profile: z.string().describe("Volatility 2 profile name"),
    },
    async ({ dump_path, profile }) => {
      const volBin = findVolatility2();
      if (!volBin) {
        const result = { error: "Volatility 2 not found." };
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      const dump = validateDump(dump_path);

      const syscall = await runCmd(
        volBin,
        [`--profile=${profile}`, "-f", dump, "linux_check_syscall"],
        { timeout: 300 }
      );
      const hidden = await runCmd(
        volBin,
        [`--profile=${profile}`, "-f", dump, "linux_hidden_modules"],
        { timeout: 300 }
      );

      const indicators: string[] = [];
      if (syscall.stdout.toUpperCase().includes("HOOKED")) {
        indicators.push("Hooked syscall entries detected — possible rootkit");
      }
      if (hidden.stdout.trim() && !hidden.stdout.includes("No")) {
        indicators.push("Hidden kernel modules found — likely rootkit");
      }

      const result = {
        syscall_check: syscall.stdout.slice(0, 3000),
        hidden_modules: hidden.stdout.slice(0, 3000),
        rootkit_indicators: indicators,
        likely_compromised: indicators.length > 0,
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );
}
