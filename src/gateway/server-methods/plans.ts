import { randomUUID } from "node:crypto";
import { ErrorCodes, errorShape } from "../protocol/index.js";
import type { GatewayRequestHandlers } from "./types.js";

// Plan data structures (matching ClydeControl's Plan.swift)
interface PlanTask {
  id: string;
  title: string;
  description?: string;
  status: "pending" | "inProgress" | "completed" | "skipped" | "blocked";
  order: number;
  startedAt?: string;
  completedAt?: string;
  notes?: string;
}

interface PlanPhase {
  id: string;
  title: string;
  description?: string;
  status: "pending" | "inProgress" | "completed" | "skipped";
  tasks: PlanTask[];
  order: number;
}

interface Plan {
  id: string;
  title: string;
  description?: string;
  status: "draft" | "approved" | "inProgress" | "paused" | "completed" | "cancelled";
  phases: PlanPhase[];
  createdAt: string;
  updatedAt: string;
  approvedAt?: string;
  completedAt?: string;
}

// In-memory plan storage (per session)
const sessionPlans = new Map<string, Plan[]>();

function getPlansForSession(sessionKey: string): Plan[] {
  if (!sessionPlans.has(sessionKey)) {
    sessionPlans.set(sessionKey, []);
  }
  return sessionPlans.get(sessionKey)!;
}

export const planHandlers: GatewayRequestHandlers = {
  // Create a new plan
  "plan.create": async ({ params, respond, context }) => {
    const p = params as {
      sessionKey: string;
      title: string;
      description?: string;
      phases?: PlanPhase[];
    };

    if (!p.sessionKey || !p.title) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "sessionKey and title required"),
      );
      return;
    }

    const now = new Date().toISOString();
    const plan: Plan = {
      id: randomUUID(),
      title: p.title,
      description: p.description,
      status: "draft",
      phases: p.phases ?? [],
      createdAt: now,
      updatedAt: now,
    };

    const plans = getPlansForSession(p.sessionKey);
    plans.push(plan);

    // Broadcast to connected clients
    context.broadcast("plan.created", { sessionKey: p.sessionKey, plan });
    context.nodeSendToSession(p.sessionKey, "plan.created", { plan });

    respond(true, { plan });
  },

  // Update a plan (status, add phases, etc.)
  "plan.update": async ({ params, respond, context }) => {
    const p = params as {
      sessionKey: string;
      planId: string;
      status?: Plan["status"];
      title?: string;
      description?: string;
      phases?: PlanPhase[];
    };

    if (!p.sessionKey || !p.planId) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "sessionKey and planId required"),
      );
      return;
    }

    const plans = getPlansForSession(p.sessionKey);
    const plan = plans.find((pl) => pl.id === p.planId);

    if (!plan) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "plan not found"));
      return;
    }

    const now = new Date().toISOString();
    if (p.status) plan.status = p.status;
    if (p.title) plan.title = p.title;
    if (p.description !== undefined) plan.description = p.description;
    if (p.phases) plan.phases = p.phases;
    plan.updatedAt = now;

    if (p.status === "approved") plan.approvedAt = now;
    if (p.status === "completed") plan.completedAt = now;

    // Broadcast update
    context.broadcast("plan.updated", { sessionKey: p.sessionKey, plan });
    context.nodeSendToSession(p.sessionKey, "plan.updated", { plan });

    respond(true, { plan });
  },

  // Update a specific task
  "plan.taskUpdate": async ({ params, respond, context }) => {
    const p = params as {
      sessionKey: string;
      planId: string;
      phaseId: string;
      taskId: string;
      status?: PlanTask["status"];
      notes?: string;
    };

    if (!p.sessionKey || !p.planId || !p.taskId) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "sessionKey, planId, and taskId required"),
      );
      return;
    }

    const plans = getPlansForSession(p.sessionKey);
    const plan = plans.find((pl) => pl.id === p.planId);

    if (!plan) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "plan not found"));
      return;
    }

    const now = new Date().toISOString();
    let taskFound = false;

    for (const phase of plan.phases) {
      const task = phase.tasks.find((t) => t.id === p.taskId);
      if (task) {
        if (p.status) {
          task.status = p.status;
          if (p.status === "inProgress") task.startedAt = now;
          if (p.status === "completed") task.completedAt = now;
        }
        if (p.notes !== undefined) task.notes = p.notes;
        taskFound = true;

        // Update phase status based on tasks
        const allComplete = phase.tasks.every(
          (t) => t.status === "completed" || t.status === "skipped",
        );
        const anyInProgress = phase.tasks.some((t) => t.status === "inProgress");
        if (allComplete) {
          phase.status = "completed";
        } else if (anyInProgress || phase.tasks.some((t) => t.status === "completed")) {
          phase.status = "inProgress";
        }

        break;
      }
    }

    if (!taskFound) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "task not found"));
      return;
    }

    plan.updatedAt = now;

    // Check if all phases complete
    if (plan.phases.every((ph) => ph.status === "completed" || ph.status === "skipped")) {
      plan.status = "completed";
      plan.completedAt = now;
    } else if (plan.phases.some((ph) => ph.status === "inProgress")) {
      plan.status = "inProgress";
    }

    // Broadcast task update
    context.broadcast("plan.taskUpdated", {
      sessionKey: p.sessionKey,
      planId: p.planId,
      phaseId: p.phaseId,
      taskId: p.taskId,
      status: p.status,
      notes: p.notes,
      plan, // Include full plan for easy client update
    });
    context.nodeSendToSession(p.sessionKey, "plan.taskUpdated", {
      planId: p.planId,
      taskId: p.taskId,
      status: p.status,
      notes: p.notes,
      plan,
    });

    respond(true, { plan });
  },

  // Get all plans for a session
  "plan.list": async ({ params, respond }) => {
    const p = params as { sessionKey: string };

    if (!p.sessionKey) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "sessionKey required"));
      return;
    }

    const plans = getPlansForSession(p.sessionKey);
    respond(true, { plans });
  },

  // Delete a plan
  "plan.delete": async ({ params, respond, context }) => {
    const p = params as { sessionKey: string; planId: string };

    if (!p.sessionKey || !p.planId) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "sessionKey and planId required"),
      );
      return;
    }

    const plans = getPlansForSession(p.sessionKey);
    const index = plans.findIndex((pl) => pl.id === p.planId);

    if (index === -1) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "plan not found"));
      return;
    }

    plans.splice(index, 1);

    context.broadcast("plan.deleted", { sessionKey: p.sessionKey, planId: p.planId });
    context.nodeSendToSession(p.sessionKey, "plan.deleted", { planId: p.planId });

    respond(true, { ok: true });
  },
};
