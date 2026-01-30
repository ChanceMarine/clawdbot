import { Type } from "@sinclair/typebox";

import { emitAgentEvent } from "../../infra/agent-events.js";
import type { AnyAgentTool } from "./common.js";
import { readStringParam } from "./common.js";

const BubbleToolSchema = Type.Object({
  action: Type.Union([Type.Literal("break"), Type.Literal("new")], {
    description:
      'Action to perform. "break" starts a new bubble within the same response turn. "new" starts a completely separate message.',
  }),
});

export function createBubbleTool(opts?: { runId?: string }): AnyAgentTool {
  return {
    label: "Bubble",
    name: "bubble",
    description:
      "Control message bubbles in chat. Use 'break' to split your response into multiple bubbles (like sending separate messages). Use 'new' to start a completely new message.",
    parameters: BubbleToolSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const action = readStringParam(params, "action", { required: true });

      if (action !== "break" && action !== "new") {
        return {
          content: [{ type: "text", text: `Invalid action: ${action}. Use "break" or "new".` }],
          details: { error: "invalid_action" },
        };
      }

      const runId = opts?.runId;
      if (!runId) {
        return {
          content: [{ type: "text", text: "Cannot emit bubble event: no runId available." }],
          details: { error: "no_run_id" },
        };
      }

      emitAgentEvent({
        runId,
        stream: "bubble",
        data: { action },
      });

      return {
        content: [
          {
            type: "text",
            text: `Bubble ${action} emitted.`,
          },
        ],
        details: { action, runId },
      };
    },
  };
}
