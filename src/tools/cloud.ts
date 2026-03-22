/**
 * Cloud Security tools.
 *
 * CloudTrail log analysis and anomaly detection using jq.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runShell, requireTool, parseLines } from "../runner.js";
import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";

export function register(server: McpServer): void {
  server.tool(
    "cloudtrail_analyze",
    "Parse and analyze AWS CloudTrail logs.\n\nExtracts event timeline, unique users, event types, and source IPs.\n\nReturns: {\"event_count\": int, \"unique_users\": [str], \"event_types\": [str], \"source_ips\": [str], \"timeline\": str}.\n\nSide effects: Read-only file analysis. Requires jq.",
    {
      log_dir: z
        .string()
        .describe("Directory containing CloudTrail JSON log files"),
    },
    async ({ log_dir }) => {
      requireTool("jq");

      const logPath = resolve(log_dir);
      if (!existsSync(logPath) || !statSync(logPath).isDirectory()) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Directory not found: ${logPath}` }),
            },
          ],
        };
      }

      // Event timeline (sorted by time)
      const timeline = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records | sort_by(.eventTime) | .[] | [.eventTime, .eventName, .sourceIPAddress, .userIdentity.userName // .userIdentity.principalId] | @tsv' 2>/dev/null | head -100`,
        { timeout: 60 }
      );

      // Unique users
      const users = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[].userIdentity | (.userName // .principalId // .arn)' 2>/dev/null | sort -u`,
        { timeout: 30 }
      );

      // Event type frequency
      const events = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[].eventName' 2>/dev/null | sort | uniq -c | sort -rn | head -30`,
        { timeout: 30 }
      );

      // Source IPs
      const ips = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[].sourceIPAddress' 2>/dev/null | sort | uniq -c | sort -rn | head -20`,
        { timeout: 30 }
      );

      // Error events
      const errors = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[] | select(.errorCode != null) | [.eventTime, .eventName, .errorCode, .errorMessage] | @tsv' 2>/dev/null | head -30`,
        { timeout: 30 }
      );

      const result = {
        timeline: timeline.stdout.slice(0, 3000),
        unique_users: parseLines(users.stdout).slice(0, 30),
        event_type_frequency: parseLines(events.stdout).slice(0, 30),
        source_ips: parseLines(ips.stdout).slice(0, 20),
        error_events: parseLines(errors.stdout).slice(0, 30),
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );

  server.tool(
    "cloudtrail_find_anomalies",
    "Find anomalies in CloudTrail logs: non-AWS IPs, unusual API calls, role assumptions.\n\nReturns: {\"non_aws_ips\": [str], \"unusual_events\": [str], \"role_assumptions\": [str], \"data_exfil_indicators\": [str]}.\n\nSide effects: Read-only file analysis.",
    {
      log_dir: z
        .string()
        .describe("Directory containing CloudTrail JSON log files"),
    },
    async ({ log_dir }) => {
      requireTool("jq");

      const logPath = resolve(log_dir);
      if (!existsSync(logPath) || !statSync(logPath).isDirectory()) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Directory not found: ${logPath}` }),
            },
          ],
        };
      }

      // All unique source IPs
      const allIps = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[].sourceIPAddress' 2>/dev/null | sort -u`,
        { timeout: 30 }
      );

      // Non-AWS IPs (not matching AWS internal patterns)
      const nonAws: string[] = [];
      for (const ip of parseLines(allIps.stdout)) {
        const trimmed = ip.trim();
        if (
          trimmed &&
          !trimmed.endsWith(".amazonaws.com") &&
          !trimmed.startsWith("AWS Internal")
        ) {
          nonAws.push(trimmed);
        }
      }

      // Role assumption events (lateral movement)
      const assumeRole = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[] | select(.eventName == "AssumeRole") | [.eventTime, .sourceIPAddress, .requestParameters.roleArn // "unknown"] | @tsv' 2>/dev/null | head -20`,
        { timeout: 30 }
      );

      // Sensitive API calls
      const sensitiveEvents = [
        "CreateUser",
        "CreateAccessKey",
        "PutUserPolicy",
        "AttachUserPolicy",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "DeleteTrail",
        "StopLogging",
        "PutBucketPolicy",
        "PutBucketAcl",
        "GetObject",
        "PutObject",
        "CreateKeyPair",
        "RunInstances",
        "AuthorizeSecurityGroupIngress",
      ];
      const sensitiveFilter = sensitiveEvents
        .map((e) => `.eventName == "${e}"`)
        .join(" or ");
      const sensitive = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[] | select(${sensitiveFilter}) | [.eventTime, .eventName, .sourceIPAddress, .userIdentity.userName // .userIdentity.principalId] | @tsv' 2>/dev/null | head -30`,
        { timeout: 30 }
      );

      // Data exfiltration indicators (GetObject, large downloads)
      const exfil = await runShell(
        `cat '${logPath}'/*.json 2>/dev/null | jq -r '.Records[] | select(.eventName == "GetObject" or .eventName == "ListBuckets" or .eventName == "ListObjects") | [.eventTime, .eventName, .sourceIPAddress, .requestParameters.bucketName // "unknown"] | @tsv' 2>/dev/null | head -30`,
        { timeout: 30 }
      );

      const result = {
        non_aws_source_ips: nonAws.slice(0, 20),
        role_assumptions: parseLines(assumeRole.stdout).slice(0, 20),
        sensitive_api_calls: parseLines(sensitive.stdout).slice(0, 30),
        data_access_events: parseLines(exfil.stdout).slice(0, 30),
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );
}
