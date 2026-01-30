/**
 * Types for the interactive approval system.
 * Used when Ask mode requires user approval for actions.
 */

export type ApprovalActionKind = "exec" | "write" | "edit";

export type ApprovalAction = {
  kind: ApprovalActionKind;
  /** For exec: the command string */
  command?: string;
  /** For write/edit: the file path */
  filePath?: string;
  /** Truncated preview of content (for write) or changes (for edit) */
  preview?: string;
  /** Original tool call arguments for retry */
  toolArgs?: Record<string, unknown>;
};

export type ApprovalRequest = {
  requestId: string;
  sessionKey: string;
  runId: string;
  action: ApprovalAction;
  timestamp: number;
};

export type ApprovalDecision = "allow-once" | "allow-session" | "allow-always" | "deny";

export type ApprovalResponse = {
  requestId: string;
  decision: ApprovalDecision;
};

export type ApprovalResult = {
  approved: boolean;
  decision: ApprovalDecision;
  /** If allow-always, the pattern to add to allowlist */
  allowlistPattern?: string;
};

/**
 * Event emitted to clients when approval is needed.
 */
export type ApprovalRequestEvent = {
  type: "approval_request";
} & ApprovalRequest;

/**
 * Event emitted when approval is resolved.
 */
export type ApprovalResolvedEvent = {
  type: "approval_resolved";
  requestId: string;
  decision: ApprovalDecision;
};
