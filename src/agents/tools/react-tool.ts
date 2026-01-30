import { Type } from "@sinclair/typebox";

import { emitAgentEvent } from "../../infra/agent-events.js";
import type { AnyAgentTool } from "./common.js";
import { readStringParam } from "./common.js";

const ReactToolSchema = Type.Object({
  emoji: Type.String({
    description: "Emoji to react with (e.g., 👍, ❤️, 😂).",
  }),
  messageId: Type.Optional(
    Type.String({
      description:
        "ID of the message to react to. If omitted, reacts to the most recent user message.",
    }),
  ),
  remove: Type.Optional(
    Type.Boolean({
      description: "If true, removes the reaction instead of adding it.",
    }),
  ),
});

export function createReactTool(opts?: { runId?: string }): AnyAgentTool {
  return {
    label: "React",
    name: "react",
    description:
      "React to a message with an emoji. Use to acknowledge, express appreciation, or respond non-verbally.",
    parameters: ReactToolSchema,
    execute: async (_toolCallId, args) => {
      const params = args as Record<string, unknown>;
      const emoji = readStringParam(params, "emoji", { required: true });
      const messageId = readStringParam(params, "messageId");
      const remove = params.remove === true;

      const runId = opts?.runId;
      if (!runId) {
        return {
          content: [{ type: "text", text: "Cannot emit reaction: no runId available." }],
          details: { error: "no_run_id" },
        };
      }

      emitAgentEvent({
        runId,
        stream: "react",
        data: {
          args: {
            emoji,
            messageId: messageId || null, // null means "most recent user message"
            remove,
            reactor: "assistant",
          },
        },
      });

      const action = remove ? "Removed" : "Added";
      const target = messageId ? `message ${messageId}` : "last user message";
      return {
        content: [
          {
            type: "text",
            text: `${action} ${emoji} reaction to ${target}.`,
          },
        ],
        details: { emoji, messageId, remove, runId },
      };
    },
  };
}
