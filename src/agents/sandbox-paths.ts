import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// Blocklist of sensitive file paths that should NEVER be readable.
// These patterns protect credentials, keys, and other sensitive data.
const SENSITIVE_PATH_PATTERNS = [
  // SSH
  /\.ssh\//i,
  /id_rsa/i,
  /id_ed25519/i,
  /id_ecdsa/i,
  /known_hosts/i,
  // AWS
  /\.aws\/credentials/i,
  /\.aws\/config/i,
  // GCP
  /\.config\/gcloud/i,
  /application_default_credentials\.json/i,
  // Azure
  /\.azure\//i,
  // Kubernetes
  /\.kube\/config/i,
  // GPG
  /\.gnupg\//i,
  // Password managers
  /\.password-store\//i,
  // Shell history (could contain secrets)
  /\.(bash|zsh|fish)_history/i,
  // Environment files
  /\.env$/i,
  /\.env\.local/i,
  /\.env\.production/i,
  // Clawdbot sensitive files - block entire config directory
  // This prevents agents from reading auth tokens, credentials, or session data
  /\.clawdbot\/clawdbot\.json/i, // Main config with auth token
  /\.clawdbot\/clawdbot\.ya?ml/i, // Alt config formats
  /\.clawdbot\/credentials/i,
  /\.clawdbot\/identity/i,
  /\.clawdbot\/devices/i, // Paired device tokens
  /\.clawdbot\/agents\/.*\/auth/i, // Agent auth profiles
  /auth-profiles\.json/i,
  /gateway\.json/i, // Gateway discovery info
  // NPM tokens
  /\.npmrc/i,
  // Git credentials
  /\.git-credentials/i,
  /\.gitconfig/i, // Can contain credentials
  // Docker
  /\.docker\/config\.json/i,
];

/**
 * Check if a file path matches any sensitive path pattern.
 * This protects credentials, keys, and other sensitive data from being read.
 */
export function isSensitivePath(filePath: string): boolean {
  const normalized = filePath.toLowerCase();
  return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(normalized));
}

/**
 * Assert that a file path is not sensitive. Throws if the path matches
 * any sensitive path pattern.
 */
export function assertNotSensitivePath(filePath: string): void {
  if (isSensitivePath(filePath)) {
    throw new Error(`Access denied: Cannot read sensitive file ${path.basename(filePath)}`);
  }
}

const UNICODE_SPACES = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;

function normalizeUnicodeSpaces(str: string): string {
  return str.replace(UNICODE_SPACES, " ");
}

function expandPath(filePath: string): string {
  const normalized = normalizeUnicodeSpaces(filePath);
  if (normalized === "~") {
    return os.homedir();
  }
  if (normalized.startsWith("~/")) {
    return os.homedir() + normalized.slice(1);
  }
  return normalized;
}

function resolveToCwd(filePath: string, cwd: string): string {
  const expanded = expandPath(filePath);
  if (path.isAbsolute(expanded)) return expanded;
  return path.resolve(cwd, expanded);
}

export function resolveSandboxPath(params: { filePath: string; cwd: string; root: string }): {
  resolved: string;
  relative: string;
} {
  const resolved = resolveToCwd(params.filePath, params.cwd);

  // Block access to sensitive credential files
  assertNotSensitivePath(resolved);

  const rootResolved = path.resolve(params.root);
  const relative = path.relative(rootResolved, resolved);
  if (!relative || relative === "") {
    return { resolved, relative: "" };
  }
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Path escapes sandbox root (${shortPath(rootResolved)}): ${params.filePath}`);
  }
  return { resolved, relative };
}

export async function assertSandboxPath(params: { filePath: string; cwd: string; root: string }) {
  const resolved = resolveSandboxPath(params);
  await assertNoSymlink(resolved.relative, path.resolve(params.root));
  return resolved;
}

async function assertNoSymlink(relative: string, root: string) {
  if (!relative) return;
  const parts = relative.split(path.sep).filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink()) {
        throw new Error(`Symlink not allowed in sandbox path: ${current}`);
      }
    } catch (err) {
      const anyErr = err as { code?: string };
      if (anyErr.code === "ENOENT") {
        return;
      }
      throw err;
    }
  }
}

function shortPath(value: string) {
  if (value.startsWith(os.homedir())) {
    return `~${value.slice(os.homedir().length)}`;
  }
  return value;
}
