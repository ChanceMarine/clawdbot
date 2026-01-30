import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Session transcript encryption using AES-256-GCM.
// Key is derived from a machine-specific secret stored in the state directory.

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const ENCRYPTED_PREFIX = "enc:v1:";

/**
 * Resolve the encryption key file path.
 * Stored in ~/.clawdbot/.session-key (hidden file, 0600 perms).
 */
function resolveKeyPath(): string {
  const stateDir = process.env.CLAWDBOT_STATE_DIR?.trim() || path.join(os.homedir(), ".clawdbot");
  return path.join(stateDir, ".session-key");
}

/**
 * Get or create the session encryption key.
 * Key is stored in a file with restrictive permissions.
 */
function getOrCreateKey(): Buffer {
  const keyPath = resolveKeyPath();

  try {
    const existingKey = fs.readFileSync(keyPath);
    if (existingKey.length === KEY_LENGTH) {
      return existingKey;
    }
  } catch {
    // Key doesn't exist, create it
  }

  // Generate a new random key
  const newKey = crypto.randomBytes(KEY_LENGTH);

  // Ensure parent directory exists
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });

  // Write key with restrictive permissions (owner read/write only)
  fs.writeFileSync(keyPath, newKey, { mode: 0o600 });

  // Double-check permissions are set correctly
  try {
    fs.chmodSync(keyPath, 0o600);
  } catch {
    // Best effort
  }

  return newKey;
}

/**
 * Check if session encryption is enabled.
 * Enabled by default, can be disabled via CLAWDBOT_SESSION_ENCRYPTION=off.
 */
export function isSessionEncryptionEnabled(): boolean {
  const env = process.env.CLAWDBOT_SESSION_ENCRYPTION?.trim().toLowerCase();
  return env !== "off" && env !== "false" && env !== "0";
}

/**
 * Encrypt session data for storage.
 * Returns the original data if encryption is disabled.
 */
export function encryptSessionData(plaintext: string): string {
  if (!isSessionEncryptionEnabled()) {
    return plaintext;
  }

  try {
    const key = getOrCreateKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);

    const authTag = cipher.getAuthTag();

    // Format: prefix + base64(iv + authTag + ciphertext)
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return ENCRYPTED_PREFIX + combined.toString("base64");
  } catch {
    // Fall back to unencrypted on error
    return plaintext;
  }
}

/**
 * Decrypt session data from storage.
 * Returns the original data if not encrypted or decryption fails.
 */
export function decryptSessionData(data: string): string {
  if (!data.startsWith(ENCRYPTED_PREFIX)) {
    // Not encrypted, return as-is
    return data;
  }

  try {
    const key = getOrCreateKey();
    const combined = Buffer.from(data.slice(ENCRYPTED_PREFIX.length), "base64");

    if (combined.length < IV_LENGTH + AUTH_TAG_LENGTH) {
      // Invalid format, return original
      return data;
    }

    const iv = combined.subarray(0, IV_LENGTH);
    const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return decrypted.toString("utf8");
  } catch {
    // Decryption failed, return original
    // This handles cases where data was not actually encrypted
    // or the key has changed
    return data;
  }
}

/**
 * Check if data is encrypted.
 */
export function isEncrypted(data: string): boolean {
  return data.startsWith(ENCRYPTED_PREFIX);
}
