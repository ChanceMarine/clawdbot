import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export type PluginVerificationResult = {
  verified: boolean;
  reason?: string;
  source: "builtin" | "local" | "external" | "unknown";
};

// Trusted plugin sources (builtin plugins)
const TRUSTED_PATHS = ["skills/", "extensions/"];

export function verifyPlugin(pluginPath: string, rootDir: string): PluginVerificationResult {
  // Check if it's a builtin plugin
  const relativePath = path.relative(rootDir, pluginPath);
  for (const trusted of TRUSTED_PATHS) {
    if (relativePath.startsWith(trusted)) {
      return { verified: true, source: "builtin" };
    }
  }

  // External plugins - warn but allow
  return {
    verified: false,
    reason: "External plugin not verified - use with caution",
    source: "external",
  };
}

/**
 * Computes a SHA-256 hash of a plugin's main entry file.
 * Can be used for integrity verification in the future.
 */
export function computePluginHash(pluginPath: string): string | null {
  try {
    if (!fs.existsSync(pluginPath)) {
      return null;
    }
    const content = fs.readFileSync(pluginPath);
    return crypto.createHash("sha256").update(content).digest("hex");
  } catch {
    return null;
  }
}

/**
 * Checks if a plugin path is within a trusted directory.
 */
export function isInTrustedPath(pluginPath: string, rootDir: string): boolean {
  const relativePath = path.relative(rootDir, pluginPath);
  // Ensure the path doesn't escape the root directory
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    return false;
  }
  return TRUSTED_PATHS.some((trusted) => relativePath.startsWith(trusted));
}

/**
 * Returns a list of security warnings for a plugin based on its verification result.
 */
export function getSecurityWarnings(result: PluginVerificationResult): string[] {
  const warnings: string[] = [];

  if (!result.verified) {
    warnings.push(result.reason ?? "Plugin verification failed");
  }

  if (result.source === "external") {
    warnings.push("External plugins may have elevated permissions");
    warnings.push("Review plugin source code before enabling");
  }

  if (result.source === "unknown") {
    warnings.push("Plugin source could not be determined");
  }

  return warnings;
}
