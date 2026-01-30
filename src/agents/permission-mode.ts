/**
 * Permission mode enforcement for file tools.
 *
 * Modes:
 * - plan: Read-only. Writes and exec blocked entirely.
 * - ask: Writes require approval via interactive prompt.
 * - auto: Full file access, exec uses normal allowlist.
 * - dangerously-skip: No restrictions at all.
 * - undefined: Same as auto (backward compat).
 */

import fs from "node:fs";
import type { AgentToolResult } from "@mariozechner/pi-agent-core";
import { requestApproval, type ApprovalAction } from "./approval/index.js";
import type { AnyAgentTool } from "./pi-tools.types.js";

function debugLog(msg: string, data?: unknown) {
  const line = `[${new Date().toISOString()}] ${msg} ${data ? JSON.stringify(data) : ""}\n`;
  fs.appendFileSync("/tmp/permission-mode-debug.log", line);
}

export type PermissionMode = "plan" | "ask" | "auto" | "dangerously-skip";

export type PermissionModeContext = {
  mode?: PermissionMode | (() => PermissionMode | undefined);
  homeDir?: string; // Always allowed (e.g., ~/clawd)
  /** Session key for approval requests */
  sessionKey?: string;
  /** Run ID for approval requests */
  runId?: string;
};

function resolveMode(context: PermissionModeContext): PermissionMode | undefined {
  const mode = context.mode;
  return typeof mode === "function" ? mode() : mode;
}

function isWithinHome(filePath: string, homeDir?: string): boolean {
  if (!homeDir) return false;
  const resolved = filePath.startsWith("~")
    ? filePath.replace("~", process.env.HOME || "")
    : filePath;
  const normalizedHome = homeDir.startsWith("~")
    ? homeDir.replace("~", process.env.HOME || "")
    : homeDir;
  return resolved.startsWith(normalizedHome);
}

export function checkPermissionMode(params: {
  operation: "read" | "write" | "exec";
  filePath?: string;
  context: PermissionModeContext;
}): { allowed: true } | { allowed: false; reason: string } {
  const { operation, filePath, context } = params;
  const mode = resolveMode(context);

  // Debug logging
  debugLog("checkPermissionMode", {
    operation,
    mode,
    filePath,
    sessionKey: context.sessionKey,
    runId: context.runId,
  });

  // No mode or dangerously-skip: allow everything
  if (!mode || mode === "dangerously-skip" || mode === "auto") {
    return { allowed: true };
  }

  // Home directory is always accessible for all operations
  if (filePath && isWithinHome(filePath, context.homeDir)) {
    return { allowed: true };
  }

  // Plan mode: read-only, block writes and exec
  if (mode === "plan") {
    if (operation === "read") {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: `🔒 Plan mode: ${operation} operations blocked. Switch to Ask or Auto mode to ${operation}.`,
    };
  }

  // Ask mode: require approval for writes and exec outside home
  if (mode === "ask") {
    if (operation === "read") {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: `🔐 Ask mode: ${operation} requires approval. File: ${filePath || "N/A"}. Approve this action or switch to Auto mode.`,
    };
  }

  return { allowed: true };
}

/**
 * Wrap a write/edit tool to check permission mode before executing.
 * In Ask mode with interactive approval enabled, will request user approval.
 */
export function wrapToolWithPermissionCheck(
  tool: AnyAgentTool,
  operation: "read" | "write",
  context: PermissionModeContext,
): AnyAgentTool {
  return {
    ...tool,
    execute: async (toolCallId, args, signal, onUpdate) => {
      const params = args && typeof args === "object" ? (args as Record<string, unknown>) : {};
      const filePath =
        typeof params.path === "string"
          ? params.path
          : typeof params.file_path === "string"
            ? params.file_path
            : undefined;

      const check = checkPermissionMode({
        operation,
        filePath,
        context,
      });

      if (!check.allowed) {
        const mode = resolveMode(context);

        // Debug: log when blocked
        debugLog("wrapTool blocked", {
          operation,
          mode,
          filePath,
          sessionKey: context.sessionKey,
          runId: context.runId,
        });

        // In Ask mode with session context, request user approval
        if (mode === "ask" && context.sessionKey && context.runId) {
          try {
            // Build preview for write operations
            let preview: string | undefined;
            if (operation === "write" && typeof params.content === "string") {
              preview =
                params.content.length > 200 ? params.content.slice(0, 200) + "..." : params.content;
            }

            const action: ApprovalAction = {
              kind: tool.name === "edit" ? "edit" : "write",
              filePath,
              preview,
              toolArgs: params,
            };

            const result = await requestApproval({
              sessionKey: context.sessionKey,
              runId: context.runId,
              action,
            });

            if (result.approved) {
              // User approved - execute the tool
              return tool.execute(toolCallId, args, signal, onUpdate);
            } else {
              // User denied
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `❌ Action denied by user: ${operation} to ${filePath || "file"}`,
                  },
                ],
                details: undefined,
              };
            }
          } catch (err) {
            // Approval timed out or was cancelled
            return {
              content: [
                {
                  type: "text" as const,
                  text: `⏱️ Approval request timed out or was cancelled for: ${operation} to ${filePath || "file"}`,
                },
              ],
              details: undefined,
            };
          }
        }

        // No interactive approval - return the error
        return {
          content: [{ type: "text" as const, text: `Error: ${check.reason}` }],
          details: undefined,
        };
      }

      return tool.execute(toolCallId, args, signal, onUpdate);
    },
  };
}
