/**
 * RPC handlers for interactive approval flow.
 */

import { resolveApproval, hasPendingApproval } from "../../agents/approval/index.js";
import type { ApprovalDecision } from "../../agents/approval/types.js";
import { ErrorCodes, errorShape } from "../protocol/index.js";
import type { GatewayRequestHandlers } from "./types.js";

function isValidDecision(value: unknown): value is ApprovalDecision {
  return (
    value === "allow-once" ||
    value === "allow-session" ||
    value === "allow-always" ||
    value === "deny"
  );
}

export const approvalHandlers: GatewayRequestHandlers = {
  "chat.approval.respond": ({ params, respond }) => {
    const p = params as { requestId?: unknown; decision?: unknown };

    const requestId = typeof p.requestId === "string" ? p.requestId.trim() : null;
    if (!requestId) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "requestId is required"));
      return;
    }

    if (!isValidDecision(p.decision)) {
      respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.INVALID_REQUEST,
          'decision must be one of: "allow-once", "allow-session", "allow-always", "deny"',
        ),
      );
      return;
    }

    // Check if the approval is still pending
    if (!hasPendingApproval(requestId)) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "Approval request not found or already resolved"),
      );
      return;
    }

    const result = resolveApproval({
      requestId,
      decision: p.decision,
    });

    if (!result.ok) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, result.error));
      return;
    }

    respond(true, { ok: true, requestId, decision: p.decision }, undefined);
  },

  "chat.approval.status": ({ params, respond }) => {
    const p = params as { requestId?: unknown };

    const requestId = typeof p.requestId === "string" ? p.requestId.trim() : null;
    if (!requestId) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "requestId is required"));
      return;
    }

    const pending = hasPendingApproval(requestId);
    respond(true, { requestId, pending }, undefined);
  },
};
