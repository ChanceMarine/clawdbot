/**
 * Rate limiter module for the Clawdbot Gateway.
 * Implements sliding window rate limiting with exponential backoff for auth failures.
 */

export type RateLimitConfig = {
  /** Max WebSocket connections per minute per IP. Default: 10. */
  connectionsPerMinute: number;
  /** Max auth failures before lockout. Default: 5. */
  authFailuresBeforeLockout: number;
  /** Auth lockout window in minutes. Default: 5. */
  authLockoutWindowMinutes: number;
  /** Max RPC calls per second per connection. Default: 100. */
  rpcCallsPerSecond: number;
  /** Cleanup interval in milliseconds. Default: 60000 (1 minute). */
  cleanupIntervalMs: number;
};

export const DEFAULT_RATE_LIMIT_CONFIG: RateLimitConfig = {
  connectionsPerMinute: 10,
  authFailuresBeforeLockout: 5,
  authLockoutWindowMinutes: 5,
  rpcCallsPerSecond: 100,
  cleanupIntervalMs: 60_000,
};

type SlidingWindowEntry = {
  timestamps: number[];
};

type AuthFailureEntry = {
  failures: number[];
  lockoutUntil: number | null;
  backoffMultiplier: number;
};

type RpcLimitEntry = {
  timestamps: number[];
};

export type RateLimitResult = {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
};

/**
 * IP-based rate limiter with sliding window algorithm.
 */
export class RateLimiter {
  private config: RateLimitConfig;

  // IP -> connection timestamps (sliding window)
  private connectionsByIp = new Map<string, SlidingWindowEntry>();

  // IP -> auth failure tracking with exponential backoff
  private authFailuresByIp = new Map<string, AuthFailureEntry>();

  // connectionId -> RPC call timestamps (sliding window)
  private rpcCallsByConnection = new Map<string, RpcLimitEntry>();

  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_RATE_LIMIT_CONFIG, ...config };
  }

  /**
   * Start periodic cleanup of stale entries.
   */
  start(): void {
    if (this.cleanupTimer) return;
    this.cleanupTimer = setInterval(() => this.cleanup(), this.config.cleanupIntervalMs);
    // Allow process to exit even if timer is running
    this.cleanupTimer.unref?.();
  }

  /**
   * Stop the cleanup timer.
   */
  stop(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Check if a new WebSocket connection is allowed for the given IP.
   */
  checkConnection(ip: string): RateLimitResult {
    const now = Date.now();
    const windowMs = 60_000; // 1 minute
    const maxConnections = this.config.connectionsPerMinute;

    let entry = this.connectionsByIp.get(ip);
    if (!entry) {
      entry = { timestamps: [] };
      this.connectionsByIp.set(ip, entry);
    }

    // Remove timestamps outside the sliding window
    const cutoff = now - windowMs;
    entry.timestamps = entry.timestamps.filter((ts) => ts > cutoff);

    if (entry.timestamps.length >= maxConnections) {
      const oldestInWindow = entry.timestamps[0] ?? now;
      const retryAfterMs = oldestInWindow + windowMs - now;
      return {
        allowed: false,
        reason: `connection rate limit exceeded: ${maxConnections} per minute`,
        retryAfterMs: Math.max(0, retryAfterMs),
      };
    }

    entry.timestamps.push(now);
    return { allowed: true };
  }

  /**
   * Check if auth attempts are allowed for the given IP (before auth attempt).
   */
  checkAuthAttempt(ip: string): RateLimitResult {
    const now = Date.now();
    const entry = this.authFailuresByIp.get(ip);

    if (entry?.lockoutUntil && now < entry.lockoutUntil) {
      return {
        allowed: false,
        reason: "auth locked out due to repeated failures",
        retryAfterMs: entry.lockoutUntil - now,
      };
    }

    return { allowed: true };
  }

  /**
   * Record a failed auth attempt and apply exponential backoff if needed.
   */
  recordAuthFailure(ip: string): RateLimitResult {
    const now = Date.now();
    const windowMs = this.config.authLockoutWindowMinutes * 60_000;
    const maxFailures = this.config.authFailuresBeforeLockout;

    let entry = this.authFailuresByIp.get(ip);
    if (!entry) {
      entry = { failures: [], lockoutUntil: null, backoffMultiplier: 1 };
      this.authFailuresByIp.set(ip, entry);
    }

    // If currently locked out, extend the lockout with exponential backoff
    if (entry.lockoutUntil && now < entry.lockoutUntil) {
      entry.backoffMultiplier = Math.min(entry.backoffMultiplier * 2, 32);
      const newLockoutMs = windowMs * entry.backoffMultiplier;
      entry.lockoutUntil = now + newLockoutMs;
      return {
        allowed: false,
        reason: "auth locked out due to repeated failures",
        retryAfterMs: newLockoutMs,
      };
    }

    // Remove failures outside the window
    const cutoff = now - windowMs;
    entry.failures = entry.failures.filter((ts) => ts > cutoff);
    entry.failures.push(now);

    if (entry.failures.length >= maxFailures) {
      const lockoutMs = windowMs * entry.backoffMultiplier;
      entry.lockoutUntil = now + lockoutMs;
      return {
        allowed: false,
        reason: `auth locked out after ${maxFailures} failures`,
        retryAfterMs: lockoutMs,
      };
    }

    return { allowed: true };
  }

  /**
   * Clear auth failure tracking for an IP after successful auth.
   */
  clearAuthFailures(ip: string): void {
    this.authFailuresByIp.delete(ip);
  }

  /**
   * Check if an RPC call is allowed for the given connection.
   */
  checkRpcCall(connectionId: string): RateLimitResult {
    const now = Date.now();
    const windowMs = 1_000; // 1 second
    const maxCalls = this.config.rpcCallsPerSecond;

    let entry = this.rpcCallsByConnection.get(connectionId);
    if (!entry) {
      entry = { timestamps: [] };
      this.rpcCallsByConnection.set(connectionId, entry);
    }

    // Remove timestamps outside the sliding window
    const cutoff = now - windowMs;
    entry.timestamps = entry.timestamps.filter((ts) => ts > cutoff);

    if (entry.timestamps.length >= maxCalls) {
      const oldestInWindow = entry.timestamps[0] ?? now;
      const retryAfterMs = oldestInWindow + windowMs - now;
      return {
        allowed: false,
        reason: `RPC rate limit exceeded: ${maxCalls} per second`,
        retryAfterMs: Math.max(0, retryAfterMs),
      };
    }

    entry.timestamps.push(now);
    return { allowed: true };
  }

  /**
   * Remove tracking for a closed connection.
   */
  removeConnection(connectionId: string): void {
    this.rpcCallsByConnection.delete(connectionId);
  }

  /**
   * Clean up stale entries to prevent memory growth.
   */
  private cleanup(): void {
    const now = Date.now();
    const connectionWindowMs = 60_000;
    const authWindowMs = this.config.authLockoutWindowMinutes * 60_000 * 32; // Max backoff
    const rpcWindowMs = 1_000;

    // Clean connection tracking
    for (const [ip, entry] of this.connectionsByIp) {
      const cutoff = now - connectionWindowMs;
      entry.timestamps = entry.timestamps.filter((ts) => ts > cutoff);
      if (entry.timestamps.length === 0) {
        this.connectionsByIp.delete(ip);
      }
    }

    // Clean auth failure tracking
    for (const [ip, entry] of this.authFailuresByIp) {
      // Remove if no lockout and no recent failures
      if (entry.lockoutUntil && now >= entry.lockoutUntil) {
        entry.lockoutUntil = null;
      }
      const cutoff = now - authWindowMs;
      entry.failures = entry.failures.filter((ts) => ts > cutoff);
      if (entry.failures.length === 0 && !entry.lockoutUntil) {
        this.authFailuresByIp.delete(ip);
      }
    }

    // Clean RPC tracking (stale connections)
    for (const [connId, entry] of this.rpcCallsByConnection) {
      const cutoff = now - rpcWindowMs - 60_000; // Keep for 1 minute after last call
      entry.timestamps = entry.timestamps.filter((ts) => ts > cutoff);
      if (entry.timestamps.length === 0) {
        this.rpcCallsByConnection.delete(connId);
      }
    }
  }

  /**
   * Get current stats for monitoring/debugging.
   */
  getStats(): {
    trackedIps: number;
    trackedAuthIps: number;
    trackedConnections: number;
    lockedOutIps: number;
  } {
    const now = Date.now();
    let lockedOutIps = 0;
    for (const entry of this.authFailuresByIp.values()) {
      if (entry.lockoutUntil && now < entry.lockoutUntil) {
        lockedOutIps++;
      }
    }
    return {
      trackedIps: this.connectionsByIp.size,
      trackedAuthIps: this.authFailuresByIp.size,
      trackedConnections: this.rpcCallsByConnection.size,
      lockedOutIps,
    };
  }
}

// Singleton instance for the gateway
let globalRateLimiter: RateLimiter | null = null;

export function getGlobalRateLimiter(): RateLimiter {
  if (!globalRateLimiter) {
    globalRateLimiter = new RateLimiter();
    globalRateLimiter.start();
  }
  return globalRateLimiter;
}

export function setGlobalRateLimiter(limiter: RateLimiter): void {
  if (globalRateLimiter) {
    globalRateLimiter.stop();
  }
  globalRateLimiter = limiter;
  limiter.start();
}

export function resetGlobalRateLimiter(): void {
  if (globalRateLimiter) {
    globalRateLimiter.stop();
    globalRateLimiter = null;
  }
}
