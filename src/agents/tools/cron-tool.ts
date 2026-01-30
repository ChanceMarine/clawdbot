import { Type } from "@sinclair/typebox";
import { normalizeCronJobCreate, normalizeCronJobPatch } from "../../cron/normalize.js";
import { loadConfig } from "../../config/config.js";
import { truncateUtf16Safe } from "../../utils.js";
import { optionalStringEnum, stringEnum } from "../schema/typebox.js";
import { resolveSessionAgentId } from "../agent-scope.js";
import { type AnyAgentTool, jsonResult, readStringParam } from "./common.js";
import { callGatewayTool, type GatewayCallOptions } from "./gateway.js";
import { resolveInternalSessionKey, resolveMainSessionAlias } from "./sessions-helpers.js";

// ============================================================================
// Cron Job Payload Security Validation
// ============================================================================

/** Maximum allowed length for cron job text payload to prevent abuse */
const CRON_TEXT_MAX_LENGTH = 10_000;

/** Maximum allowed length for cron expression to prevent abuse */
const CRON_EXPRESSION_MAX_LENGTH = 100;

/** Patterns that could indicate injection attempts in cron payloads */
const SUSPICIOUS_PATTERNS = [
  // Shell injection patterns
  /;\s*(?:rm|wget|curl|bash|sh|python|perl|ruby|nc|netcat)\s/i,
  /\$\([^)]+\)/,
  /`[^`]+`/,
  // Script injection patterns
  /<script[\s>]/i,
  /javascript:/i,
  // SQL injection patterns
  /(?:union\s+select|drop\s+table|delete\s+from|insert\s+into)\s/i,
  // Path traversal
  /\.\.[\/\\]/,
];

/**
 * Validates a cron job payload for security issues.
 * Checks for:
 * - Excessive payload size
 * - Suspicious patterns that could indicate injection
 * - Invalid cron expressions
 *
 * @param job The cron job object to validate
 * @returns Object with isValid boolean and reason string
 */
export function validateCronJobPayload(job: unknown): { isValid: boolean; reason: string } {
  if (!job || typeof job !== "object") {
    return { isValid: false, reason: "Job must be a non-null object" };
  }

  const jobObj = job as Record<string, unknown>;

  // Validate cron expression length
  if (typeof jobObj.cron === "string" && jobObj.cron.length > CRON_EXPRESSION_MAX_LENGTH) {
    return {
      isValid: false,
      reason: `Cron expression exceeds maximum length of ${CRON_EXPRESSION_MAX_LENGTH} characters`,
    };
  }

  // Validate payload if present
  const payload = jobObj.payload;
  if (payload && typeof payload === "object") {
    const payloadObj = payload as Record<string, unknown>;

    // Check text field length
    if (typeof payloadObj.text === "string") {
      if (payloadObj.text.length > CRON_TEXT_MAX_LENGTH) {
        return {
          isValid: false,
          reason: `Payload text exceeds maximum length of ${CRON_TEXT_MAX_LENGTH} characters`,
        };
      }

      // Check for suspicious patterns
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(payloadObj.text)) {
          return {
            isValid: false,
            reason: `Payload text contains suspicious pattern that may indicate injection attempt`,
          };
        }
      }
    }

    // Check for unexpected executable fields
    if ("command" in payloadObj || "script" in payloadObj || "exec" in payloadObj) {
      return {
        isValid: false,
        reason: "Payload contains disallowed executable field (command/script/exec)",
      };
    }
  }

  // Validate name/description fields for injection
  for (const field of ["name", "description", "note"]) {
    if (typeof jobObj[field] === "string") {
      const value = jobObj[field] as string;
      if (value.length > 500) {
        return {
          isValid: false,
          reason: `Field "${field}" exceeds maximum length of 500 characters`,
        };
      }
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(value)) {
          return {
            isValid: false,
            reason: `Field "${field}" contains suspicious pattern that may indicate injection attempt`,
          };
        }
      }
    }
  }

  return { isValid: true, reason: "Payload validation passed" };
}

/**
 * Validates a cron job patch for security issues.
 * Similar to validateCronJobPayload but for partial updates.
 */
export function validateCronJobPatch(patch: unknown): { isValid: boolean; reason: string } {
  if (!patch || typeof patch !== "object") {
    return { isValid: false, reason: "Patch must be a non-null object" };
  }

  // Use the same validation logic as job creation
  return validateCronJobPayload(patch);
}

// NOTE: We use Type.Object({}, { additionalProperties: true }) for job/patch
// instead of CronAddParamsSchema/CronJobPatchSchema because the gateway schemas
// contain nested unions. Tool schemas need to stay provider-friendly, so we
// accept "any object" here and validate at runtime.

const CRON_ACTIONS = ["status", "list", "add", "update", "remove", "run", "runs", "wake"] as const;

const CRON_WAKE_MODES = ["now", "next-heartbeat"] as const;

const REMINDER_CONTEXT_MESSAGES_MAX = 10;
const REMINDER_CONTEXT_PER_MESSAGE_MAX = 220;
const REMINDER_CONTEXT_TOTAL_MAX = 700;
const REMINDER_CONTEXT_MARKER = "\n\nRecent context:\n";

// Flattened schema: runtime validates per-action requirements.
const CronToolSchema = Type.Object({
  action: stringEnum(CRON_ACTIONS),
  gatewayUrl: Type.Optional(Type.String()),
  gatewayToken: Type.Optional(Type.String()),
  timeoutMs: Type.Optional(Type.Number()),
  includeDisabled: Type.Optional(Type.Boolean()),
  job: Type.Optional(Type.Object({}, { additionalProperties: true })),
  jobId: Type.Optional(Type.String()),
  id: Type.Optional(Type.String()),
  patch: Type.Optional(Type.Object({}, { additionalProperties: true })),
  text: Type.Optional(Type.String()),
  mode: optionalStringEnum(CRON_WAKE_MODES),
  contextMessages: Type.Optional(
    Type.Number({ minimum: 0, maximum: REMINDER_CONTEXT_MESSAGES_MAX }),
  ),
});

type CronToolOptions = {
  agentSessionKey?: string;
};

type ChatMessage = {
  role?: unknown;
  content?: unknown;
};

function stripExistingContext(text: string) {
  const index = text.indexOf(REMINDER_CONTEXT_MARKER);
  if (index === -1) return text;
  return text.slice(0, index).trim();
}

function truncateText(input: string, maxLen: number) {
  if (input.length <= maxLen) return input;
  const truncated = truncateUtf16Safe(input, Math.max(0, maxLen - 3)).trimEnd();
  return `${truncated}...`;
}

function normalizeContextText(raw: string) {
  return raw.replace(/\s+/g, " ").trim();
}

function extractMessageText(message: ChatMessage): { role: string; text: string } | null {
  const role = typeof message.role === "string" ? message.role : "";
  if (role !== "user" && role !== "assistant") return null;
  const content = message.content;
  if (typeof content === "string") {
    const normalized = normalizeContextText(content);
    return normalized ? { role, text: normalized } : null;
  }
  if (!Array.isArray(content)) return null;
  const chunks: string[] = [];
  for (const block of content) {
    if (!block || typeof block !== "object") continue;
    if ((block as { type?: unknown }).type !== "text") continue;
    const text = (block as { text?: unknown }).text;
    if (typeof text === "string" && text.trim()) {
      chunks.push(text);
    }
  }
  const joined = normalizeContextText(chunks.join(" "));
  return joined ? { role, text: joined } : null;
}

async function buildReminderContextLines(params: {
  agentSessionKey?: string;
  gatewayOpts: GatewayCallOptions;
  contextMessages: number;
}) {
  const maxMessages = Math.min(
    REMINDER_CONTEXT_MESSAGES_MAX,
    Math.max(0, Math.floor(params.contextMessages)),
  );
  if (maxMessages <= 0) return [];
  const sessionKey = params.agentSessionKey?.trim();
  if (!sessionKey) return [];
  const cfg = loadConfig();
  const { mainKey, alias } = resolveMainSessionAlias(cfg);
  const resolvedKey = resolveInternalSessionKey({ key: sessionKey, alias, mainKey });
  try {
    const res = (await callGatewayTool("chat.history", params.gatewayOpts, {
      sessionKey: resolvedKey,
      limit: maxMessages,
    })) as { messages?: unknown[] };
    const messages = Array.isArray(res?.messages) ? res.messages : [];
    const parsed = messages
      .map((msg) => extractMessageText(msg as ChatMessage))
      .filter((msg): msg is { role: string; text: string } => Boolean(msg));
    const recent = parsed.slice(-maxMessages);
    if (recent.length === 0) return [];
    const lines: string[] = [];
    let total = 0;
    for (const entry of recent) {
      const label = entry.role === "user" ? "User" : "Assistant";
      const text = truncateText(entry.text, REMINDER_CONTEXT_PER_MESSAGE_MAX);
      const line = `- ${label}: ${text}`;
      total += line.length;
      if (total > REMINDER_CONTEXT_TOTAL_MAX) break;
      lines.push(line);
    }
    return lines;
  } catch {
    return [];
  }
}

export function createCronTool(opts?: CronToolOptions): AnyAgentTool {
  return {
    label: "Cron",
    name: "cron",
    description:
      "Manage Gateway cron jobs (status/list/add/update/remove/run/runs) and send wake events. Use `jobId` as the canonical identifier; `id` is accepted for compatibility. Use `contextMessages` (0-10) to add previous messages as context to the job text.",
    parameters: CronToolSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const action = readStringParam(params, "action", { required: true });
      const gatewayOpts: GatewayCallOptions = {
        gatewayUrl: readStringParam(params, "gatewayUrl", { trim: false }),
        gatewayToken: readStringParam(params, "gatewayToken", { trim: false }),
        timeoutMs: typeof params.timeoutMs === "number" ? params.timeoutMs : undefined,
      };

      switch (action) {
        case "status":
          return jsonResult(await callGatewayTool("cron.status", gatewayOpts, {}));
        case "list":
          return jsonResult(
            await callGatewayTool("cron.list", gatewayOpts, {
              includeDisabled: Boolean(params.includeDisabled),
            }),
          );
        case "add": {
          if (!params.job || typeof params.job !== "object") {
            throw new Error("job required");
          }
          const job = normalizeCronJobCreate(params.job) ?? params.job;
          // Validate job payload for security before creating
          const jobValidation = validateCronJobPayload(job);
          if (!jobValidation.isValid) {
            throw new Error(`Cron job validation failed: ${jobValidation.reason}`);
          }
          if (job && typeof job === "object" && !("agentId" in job)) {
            const cfg = loadConfig();
            const agentId = opts?.agentSessionKey
              ? resolveSessionAgentId({ sessionKey: opts.agentSessionKey, config: cfg })
              : undefined;
            if (agentId) {
              (job as { agentId?: string }).agentId = agentId;
            }
          }
          const contextMessages =
            typeof params.contextMessages === "number" && Number.isFinite(params.contextMessages)
              ? params.contextMessages
              : 0;
          if (
            job &&
            typeof job === "object" &&
            "payload" in job &&
            (job as { payload?: { kind?: string; text?: string } }).payload?.kind === "systemEvent"
          ) {
            const payload = (job as { payload: { kind: string; text: string } }).payload;
            if (typeof payload.text === "string" && payload.text.trim()) {
              const contextLines = await buildReminderContextLines({
                agentSessionKey: opts?.agentSessionKey,
                gatewayOpts,
                contextMessages,
              });
              if (contextLines.length > 0) {
                const baseText = stripExistingContext(payload.text);
                payload.text = `${baseText}${REMINDER_CONTEXT_MARKER}${contextLines.join("\n")}`;
              }
            }
          }
          return jsonResult(await callGatewayTool("cron.add", gatewayOpts, job));
        }
        case "update": {
          const id = readStringParam(params, "jobId") ?? readStringParam(params, "id");
          if (!id) {
            throw new Error("jobId required (id accepted for backward compatibility)");
          }
          if (!params.patch || typeof params.patch !== "object") {
            throw new Error("patch required");
          }
          const patch = normalizeCronJobPatch(params.patch) ?? params.patch;
          // Validate patch payload for security before updating
          const patchValidation = validateCronJobPatch(patch);
          if (!patchValidation.isValid) {
            throw new Error(`Cron job patch validation failed: ${patchValidation.reason}`);
          }
          return jsonResult(
            await callGatewayTool("cron.update", gatewayOpts, {
              id,
              patch,
            }),
          );
        }
        case "remove": {
          const id = readStringParam(params, "jobId") ?? readStringParam(params, "id");
          if (!id) {
            throw new Error("jobId required (id accepted for backward compatibility)");
          }
          return jsonResult(await callGatewayTool("cron.remove", gatewayOpts, { id }));
        }
        case "run": {
          const id = readStringParam(params, "jobId") ?? readStringParam(params, "id");
          if (!id) {
            throw new Error("jobId required (id accepted for backward compatibility)");
          }
          return jsonResult(await callGatewayTool("cron.run", gatewayOpts, { id }));
        }
        case "runs": {
          const id = readStringParam(params, "jobId") ?? readStringParam(params, "id");
          if (!id) {
            throw new Error("jobId required (id accepted for backward compatibility)");
          }
          return jsonResult(await callGatewayTool("cron.runs", gatewayOpts, { id }));
        }
        case "wake": {
          const text = readStringParam(params, "text", { required: true });
          const mode =
            params.mode === "now" || params.mode === "next-heartbeat"
              ? params.mode
              : "next-heartbeat";
          return jsonResult(
            await callGatewayTool("wake", gatewayOpts, { mode, text }, { expectFinal: false }),
          );
        }
        default:
          throw new Error(`Unknown action: ${action}`);
      }
    },
  };
}
