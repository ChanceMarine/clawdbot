import { randomUUID } from "node:crypto";

import type { WebSocket, WebSocketServer } from "ws";
import { resolveCanvasHostUrl } from "../../infra/canvas-host-url.js";
import { listSystemPresence, upsertPresence } from "../../infra/system-presence.js";
import type { createSubsystemLogger } from "../../logging/subsystem.js";
import { isWebchatClient } from "../../utils/message-channel.js";

import type { ResolvedGatewayAuth } from "../auth.js";
import { isLoopbackAddress } from "../net.js";
import { getGlobalRateLimiter } from "../rate-limiter.js";
import { getHandshakeTimeoutMs } from "../server-constants.js";
import type { GatewayRequestContext, GatewayRequestHandlers } from "../server-methods/types.js";
import { formatError } from "../server-utils.js";
import { logWs } from "../ws-log.js";
import { getHealthVersion, getPresenceVersion, incrementPresenceVersion } from "./health-state.js";
import { attachGatewayWsMessageHandler } from "./ws-connection/message-handler.js";
import type { GatewayWsClient } from "./ws-types.js";

type SubsystemLogger = ReturnType<typeof createSubsystemLogger>;

function validateWebSocketOrigin(params: {
  origin: string | undefined;
  remoteAddr: string | undefined;
  allowedOrigins?: string[];
}): { valid: boolean; reason?: string } {
  const { origin, remoteAddr, allowedOrigins } = params;

  // Always allow loopback connections (local development)
  if (
    remoteAddr &&
    (remoteAddr === "127.0.0.1" ||
      remoteAddr === "::1" ||
      remoteAddr.startsWith("127.") ||
      remoteAddr.startsWith("::ffff:127."))
  ) {
    return { valid: true };
  }

  // Non-browser clients may not send origin - allow these
  if (!origin) {
    return { valid: true };
  }

  // Parse and validate origin
  let originHost: string;
  try {
    const url = new URL(origin);
    originHost = url.hostname;
  } catch {
    return { valid: false, reason: "invalid_origin_format" };
  }

  // Allow localhost origins
  if (originHost === "localhost" || originHost === "127.0.0.1" || originHost === "::1") {
    return { valid: true };
  }

  // Allow Tailscale origins (*.ts.net)
  if (originHost.endsWith(".ts.net")) {
    return { valid: true };
  }

  // If no allowlist configured, reject unknown origins for security
  if (!allowedOrigins || allowedOrigins.length === 0) {
    return { valid: false, reason: "origin_not_in_allowlist" };
  }

  // Check allowlist
  for (const allowed of allowedOrigins) {
    if (origin === allowed || originHost === allowed) {
      return { valid: true };
    }
    if (allowed.startsWith("*.")) {
      const domain = allowed.slice(2);
      if (originHost === domain || originHost.endsWith(`.${domain}`)) {
        return { valid: true };
      }
    }
  }

  return { valid: false, reason: "origin_not_allowed" };
}

export function attachGatewayWsConnectionHandler(params: {
  wss: WebSocketServer;
  clients: Set<GatewayWsClient>;
  port: number;
  gatewayHost?: string;
  canvasHostEnabled: boolean;
  canvasHostServerPort?: number;
  resolvedAuth: ResolvedGatewayAuth;
  gatewayMethods: string[];
  events: string[];
  logGateway: SubsystemLogger;
  logHealth: SubsystemLogger;
  logWsControl: SubsystemLogger;
  extraHandlers: GatewayRequestHandlers;
  broadcast: (
    event: string,
    payload: unknown,
    opts?: {
      dropIfSlow?: boolean;
      stateVersion?: { presence?: number; health?: number };
    },
  ) => void;
  buildRequestContext: () => GatewayRequestContext;
}) {
  const {
    wss,
    clients,
    port,
    gatewayHost,
    canvasHostEnabled,
    canvasHostServerPort,
    resolvedAuth,
    gatewayMethods,
    events,
    logGateway,
    logHealth,
    logWsControl,
    extraHandlers,
    broadcast,
    buildRequestContext,
  } = params;

  wss.on("connection", (socket, upgradeReq) => {
    let client: GatewayWsClient | null = null;
    let closed = false;
    const openedAt = Date.now();
    const connId = randomUUID();
    const remoteAddr = (socket as WebSocket & { _socket?: { remoteAddress?: string } })._socket
      ?.remoteAddress;
    const headerValue = (value: string | string[] | undefined) =>
      Array.isArray(value) ? value[0] : value;
    const requestHost = headerValue(upgradeReq.headers.host);
    const requestOrigin = headerValue(upgradeReq.headers.origin);
    const requestUserAgent = headerValue(upgradeReq.headers["user-agent"]);
    const forwardedFor = headerValue(upgradeReq.headers["x-forwarded-for"]);

    // Rate limit check for new connections
    const clientIp = forwardedFor?.split(",")[0]?.trim() || remoteAddr || "unknown";
    const rateLimiter = getGlobalRateLimiter();
    const connectionCheck = rateLimiter.checkConnection(clientIp);

    if (!connectionCheck.allowed) {
      logWsControl.warn(`Rate limited connection from ${clientIp}: ${connectionCheck.reason}`, {
        retryAfterMs: connectionCheck.retryAfterMs,
      });
      socket.close(1008, connectionCheck.reason ?? "rate limited");
      return;
    }

    // Origin validation to prevent cross-site WebSocket hijacking
    const originCheck = validateWebSocketOrigin({
      origin: requestOrigin,
      remoteAddr,
      allowedOrigins: [], // Could be made configurable
    });

    if (!originCheck.valid) {
      logWsControl.warn(
        `Origin rejected: ${requestOrigin} from ${remoteAddr}: ${originCheck.reason}`,
      );
      socket.close(1008, originCheck.reason ?? "origin not allowed");
      return;
    }

    const canvasHostPortForWs = canvasHostServerPort ?? (canvasHostEnabled ? port : undefined);
    const canvasHostOverride =
      gatewayHost && gatewayHost !== "0.0.0.0" && gatewayHost !== "::" ? gatewayHost : undefined;
    const canvasHostUrl = resolveCanvasHostUrl({
      canvasPort: canvasHostPortForWs,
      hostOverride: canvasHostServerPort ? canvasHostOverride : undefined,
      requestHost: upgradeReq.headers.host,
      forwardedProto: upgradeReq.headers["x-forwarded-proto"],
      localAddress: upgradeReq.socket?.localAddress,
    });

    logWs("in", "open", { connId, remoteAddr });
    let handshakeState: "pending" | "connected" | "failed" = "pending";
    let closeCause: string | undefined;
    let closeMeta: Record<string, unknown> = {};
    let lastFrameType: string | undefined;
    let lastFrameMethod: string | undefined;
    let lastFrameId: string | undefined;

    const setCloseCause = (cause: string, meta?: Record<string, unknown>) => {
      if (!closeCause) closeCause = cause;
      if (meta && Object.keys(meta).length > 0) {
        closeMeta = { ...closeMeta, ...meta };
      }
    };

    const setLastFrameMeta = (meta: { type?: string; method?: string; id?: string }) => {
      if (meta.type || meta.method || meta.id) {
        lastFrameType = meta.type ?? lastFrameType;
        lastFrameMethod = meta.method ?? lastFrameMethod;
        lastFrameId = meta.id ?? lastFrameId;
      }
    };

    const send = (obj: unknown) => {
      try {
        socket.send(JSON.stringify(obj));
      } catch {
        /* ignore */
      }
    };

    const connectNonce = randomUUID();
    send({
      type: "event",
      event: "connect.challenge",
      payload: { nonce: connectNonce, ts: Date.now() },
    });

    const close = (code = 1000, reason?: string) => {
      if (closed) return;
      closed = true;
      clearTimeout(handshakeTimer);
      if (client) clients.delete(client);
      try {
        socket.close(code, reason);
      } catch {
        /* ignore */
      }
    };

    socket.once("error", (err) => {
      logWsControl.warn(`error conn=${connId} remote=${remoteAddr ?? "?"}: ${formatError(err)}`);
      close();
    });

    const isNoisySwiftPmHelperClose = (userAgent: string | undefined, remote: string | undefined) =>
      Boolean(
        userAgent?.toLowerCase().includes("swiftpm-testing-helper") && isLoopbackAddress(remote),
      );

    socket.once("close", (code, reason) => {
      const durationMs = Date.now() - openedAt;
      const closeContext = {
        cause: closeCause,
        handshake: handshakeState,
        durationMs,
        lastFrameType,
        lastFrameMethod,
        lastFrameId,
        host: requestHost,
        origin: requestOrigin,
        userAgent: requestUserAgent,
        forwardedFor,
        ...closeMeta,
      };
      if (!client) {
        const logFn = isNoisySwiftPmHelperClose(requestUserAgent, remoteAddr)
          ? logWsControl.debug
          : logWsControl.warn;
        logFn(
          `closed before connect conn=${connId} remote=${remoteAddr ?? "?"} fwd=${forwardedFor ?? "n/a"} origin=${requestOrigin ?? "n/a"} host=${requestHost ?? "n/a"} ua=${requestUserAgent ?? "n/a"} code=${code ?? "n/a"} reason=${reason?.toString() || "n/a"}`,
          closeContext,
        );
      }
      if (client && isWebchatClient(client.connect.client)) {
        logWsControl.info(
          `webchat disconnected code=${code} reason=${reason?.toString() || "n/a"} conn=${connId}`,
        );
      }
      if (client?.presenceKey) {
        upsertPresence(client.presenceKey, { reason: "disconnect" });
        incrementPresenceVersion();
        broadcast(
          "presence",
          { presence: listSystemPresence() },
          {
            dropIfSlow: true,
            stateVersion: {
              presence: getPresenceVersion(),
              health: getHealthVersion(),
            },
          },
        );
      }
      if (client?.connect?.role === "node") {
        const context = buildRequestContext();
        const nodeId = context.nodeRegistry.unregister(connId);
        if (nodeId) {
          context.nodeUnsubscribeAll(nodeId);
        }
      }
      // In the close handler
      rateLimiter.removeConnection(connId);

      logWs("out", "close", {
        connId,
        code,
        reason: reason?.toString(),
        durationMs,
        cause: closeCause,
        handshake: handshakeState,
        lastFrameType,
        lastFrameMethod,
        lastFrameId,
      });
      close();
    });

    const handshakeTimeoutMs = getHandshakeTimeoutMs();
    const handshakeTimer = setTimeout(() => {
      if (!client) {
        handshakeState = "failed";
        setCloseCause("handshake-timeout", {
          handshakeMs: Date.now() - openedAt,
        });
        logWsControl.warn(`handshake timeout conn=${connId} remote=${remoteAddr ?? "?"}`);
        close();
      }
    }, handshakeTimeoutMs);

    attachGatewayWsMessageHandler({
      socket,
      upgradeReq,
      connId,
      remoteAddr,
      forwardedFor,
      requestHost,
      requestOrigin,
      requestUserAgent,
      canvasHostUrl,
      connectNonce,
      resolvedAuth,
      gatewayMethods,
      events,
      extraHandlers,
      buildRequestContext,
      send,
      close,
      isClosed: () => closed,
      clearHandshakeTimer: () => clearTimeout(handshakeTimer),
      getClient: () => client,
      setClient: (next) => {
        client = next;
        clients.add(next);
      },
      setHandshakeState: (next) => {
        handshakeState = next;
      },
      setCloseCause,
      setLastFrameMeta,
      logGateway,
      logHealth,
      logWsControl,
    });
  });
}
