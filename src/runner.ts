/**
 * Subprocess runner utilities shared across all tool modules.
 */

import { execFile, exec } from "node:child_process";
import { promisify } from "node:util";
import { execSync } from "node:child_process";

const execFileAsync = promisify(execFile);
const execAsync = promisify(exec);

export interface CmdResult {
  stdout: string;
  stderr: string;
  returncode: number;
  success: boolean;
  command: string;
}

export interface CmdOptions {
  timeout?: number;
  stdinData?: string;
}

/**
 * Run a command with arguments (no shell interpretation).
 * Equivalent to Python's asyncio.create_subprocess_exec.
 */
export async function runCmd(
  cmd: string,
  args: string[],
  opts: CmdOptions = {}
): Promise<CmdResult> {
  const timeout = (opts.timeout ?? 120) * 1000;
  const command = [cmd, ...args].join(" ");

  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      timeout,
      maxBuffer: 50 * 1024 * 1024,
      encoding: "utf-8",
      ...(opts.stdinData ? { input: opts.stdinData } : {}),
    } as any);

    return {
      stdout: (stdout ?? "").toString().trim(),
      stderr: (stderr ?? "").toString().trim(),
      returncode: 0,
      success: true,
      command,
    };
  } catch (err: any) {
    if (err.killed || err.signal === "SIGTERM") {
      return {
        stdout: "",
        stderr: `Command timed out after ${opts.timeout ?? 120}s`,
        returncode: -1,
        success: false,
        command,
      };
    }
    return {
      stdout: (err.stdout ?? "").trim(),
      stderr: (err.stderr ?? "").trim(),
      returncode: err.code ?? 1,
      success: false,
      command,
    };
  }
}

/**
 * Run a shell command string (allows pipes, redirects, etc.).
 * Equivalent to Python's asyncio.create_subprocess_shell.
 */
export async function runShell(
  shellCmd: string,
  opts: Omit<CmdOptions, "stdinData"> = {}
): Promise<CmdResult> {
  const timeout = (opts.timeout ?? 120) * 1000;

  try {
    const { stdout, stderr } = await execAsync(shellCmd, {
      timeout,
      maxBuffer: 50 * 1024 * 1024,
    });

    return {
      stdout: (stdout ?? "").trim(),
      stderr: (stderr ?? "").trim(),
      returncode: 0,
      success: true,
      command: shellCmd,
    };
  } catch (err: any) {
    if (err.killed || err.signal === "SIGTERM") {
      return {
        stdout: "",
        stderr: `Command timed out after ${opts.timeout ?? 120}s`,
        returncode: -1,
        success: false,
        command: shellCmd,
      };
    }
    return {
      stdout: (err.stdout ?? "").trim(),
      stderr: (err.stderr ?? "").trim(),
      returncode: err.code ?? 1,
      success: false,
      command: shellCmd,
    };
  }
}

/**
 * Check that a CLI tool exists on PATH. Throws if not found.
 */
export function requireTool(name: string): string {
  try {
    const path = execSync(`which ${name}`, { encoding: "utf-8" }).trim();
    if (!path) throw new Error();
    return path;
  } catch {
    throw new Error(
      `Required tool '${name}' not found on PATH. ` +
        `Install it first (e.g., 'brew install ${name}' or 'apt install ${name}').`
    );
  }
}

/**
 * Split text into non-empty lines.
 */
export function parseLines(text: string): string[] {
  return text.split("\n").filter((line) => line.trim());
}

/**
 * Attempt to parse JSON; return raw string on failure.
 */
export function tryParseJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
