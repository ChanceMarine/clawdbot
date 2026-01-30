/**
 * Approval Manager - handles pending approval requests and coordinates
 * between agent runs and client responses.
 */

import crypto from "node:crypto";
import type { ApprovalAction, ApprovalDecision, ApprovalRequest, ApprovalResult } from "./types.js";

type PendingApproval = {
  request: ApprovalRequest;
  resolve: (result: ApprovalResult) => void;
  reject: (error: Error) => void;
  timeoutId: NodeJS.Timeout;
};

const pendingApprovals = new Map<string, PendingApproval>();

// Default timeout for approval requests (30 minutes - give user time to respond)
const DEFAULT_APPROVAL_TIMEOUT_MS = 30 * 60 * 1000;

/**
 * Emitter function type - set by gateway to broadcast events.
 */
type ApprovalEventEmitter = (event: {
  sessionKey: string;
  runId: string;
  data: Record<string, unknown>;
}) => void;

let eventEmitter: ApprovalEventEmitter | null = null;

/**
 * Set the event emitter for broadcasting approval requests to clients.
 */
export function setApprovalEventEmitter(emitter: ApprovalEventEmitter): void {
  eventEmitter = emitter;
}

/**
 * Request approval for an action. Returns a promise that resolves when
 * the user responds or rejects on timeout.
 */
export async function requestApproval(params: {
  sessionKey: string;
  runId: string;
  action: ApprovalAction;
  timeoutMs?: number;
}): Promise<ApprovalResult> {
  const { sessionKey, runId, action } = params;
  const timeoutMs = params.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;

  const requestId = crypto.randomUUID();
  const request: ApprovalRequest = {
    requestId,
    sessionKey,
    runId,
    action,
    timestamp: Date.now(),
  };

  return new Promise((resolve, reject) => {
    // Set up timeout
    const timeoutId = setTimeout(() => {
      const pending = pendingApprovals.get(requestId);
      if (pending) {
        pendingApprovals.delete(requestId);
        reject(new Error("Approval request timed out"));
      }
    }, timeoutMs);

    // Store pending approval
    pendingApprovals.set(requestId, {
      request,
      resolve,
      reject,
      timeoutId,
    });

    // Emit event to clients
    if (eventEmitter) {
      eventEmitter({
        sessionKey,
        runId,
        data: {
          type: "approval_request",
          ...request,
        },
      });
    }
  });
}

/**
 * Resolve a pending approval request with a decision.
 * Called when the user responds via the chat UI.
 */
export function resolveApproval(params: {
  requestId: string;
  decision: ApprovalDecision;
}): { ok: true } | { ok: false; error: string } {
  const { requestId, decision } = params;

  const pending = pendingApprovals.get(requestId);
  if (!pending) {
    return { ok: false, error: "Approval request not found or already resolved" };
  }

  // Clear timeout and remove from pending
  clearTimeout(pending.timeoutId);
  pendingApprovals.delete(requestId);

  // Build allowlist pattern if always-allow
  let allowlistPattern: string | undefined;
  if (decision === "allow-always") {
    const action = pending.request.action;
    if (action.kind === "exec" && action.command) {
      // Extract executable path for allowlist
      const firstToken = action.command.trim().split(/\s+/)[0];
      allowlistPattern = firstToken;
    } else if ((action.kind === "write" || action.kind === "edit") && action.filePath) {
      // Use file path pattern
      allowlistPattern = action.filePath;
    }
  }

  // Resolve the promise
  pending.resolve({
    approved: decision !== "deny",
    decision,
    allowlistPattern,
  });

  // Emit resolution event
  if (eventEmitter) {
    eventEmitter({
      sessionKey: pending.request.sessionKey,
      runId: pending.request.runId,
      data: {
        type: "approval_resolved",
        requestId,
        decision,
      },
    });
  }

  return { ok: true };
}

/**
 * Cancel all pending approvals for a session (e.g., on disconnect or abort).
 */
export function cancelApprovalsForSession(sessionKey: string): void {
  for (const [requestId, pending] of pendingApprovals) {
    if (pending.request.sessionKey === sessionKey) {
      clearTimeout(pending.timeoutId);
      pendingApprovals.delete(requestId);
      pending.reject(new Error("Approval cancelled"));
    }
  }
}

/**
 * Cancel all pending approvals for a run (e.g., on run abort).
 */
export function cancelApprovalsForRun(runId: string): void {
  for (const [requestId, pending] of pendingApprovals) {
    if (pending.request.runId === runId) {
      clearTimeout(pending.timeoutId);
      pendingApprovals.delete(requestId);
      pending.reject(new Error("Approval cancelled - run aborted"));
    }
  }
}

/**
 * Get count of pending approvals (for debugging/status).
 */
export function getPendingApprovalCount(): number {
  return pendingApprovals.size;
}

/**
 * Check if there's a pending approval for a request ID.
 */
export function hasPendingApproval(requestId: string): boolean {
  return pendingApprovals.has(requestId);
}
