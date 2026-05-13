/**
 * EncryptedFileBackend — AES-256-GCM encrypted JSON store.
 *
 * Universal fallback that works on every platform. Stores secrets in an
 * encrypted file at ~/.pi/agent/secrets.enc. The encryption key is derived
 * from a machine-stable secret (host id + machine-id) so it is transparent
 * to the user — no passphrase required.
 *
 * Format:
 *   [16-byte IV][16-byte auth tag][ciphertext]
 *   Ciphertext is JSON: { version: 1, secrets: { key: value, ... } }
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { resolve, dirname } from "node:path";
import type { SecretBackend } from "./interface.js";

// =============================================================================
// Constants
// =============================================================================

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

const DEFAULT_PATH = resolve(homedir(), ".pi", "agent", "secrets.enc");

// =============================================================================
// Encryption helpers
// =============================================================================

/**
 * Derive a 256-bit key from machine-stable identifiers.
 * This is not a password — it's a deterministic seed so the file is
 * transparently decryptable by the same machine without user interaction.
 * On first use, we also store a random salt alongside the file for key
 * derivation, making the key unique per-machine even if machine-id is same.
 */
function deriveKey(salt: Buffer): Buffer {
  // Combine machine-id, hostname, and salt into a deterministic key
  const machineId = readMachineId();
  const seed = `${machineId}::secret-store-v1::${salt.toString("hex")}`;
  return createHash("sha256").update(seed, "utf-8").digest();
}

function readMachineId(): string {
  try {
    const { readFileSync } = require("node:fs") as typeof import("node:fs");
    // Try various machine-id locations
    for (const p of ["/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"]) {
      if (existsSync(p)) {
        return readFileSync(p, "utf-8").trim();
      }
    }
  } catch {
    // fall through
  }
  // Fallback: hostname + random seed stored alongside the file
  return hostname();
}

function encrypt(plaintext: string, key: Buffer): { iv: Buffer; tag: Buffer; ciphertext: Buffer } {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, tag, ciphertext: encrypted };
}

function decrypt(data: { iv: Buffer; tag: Buffer; ciphertext: Buffer }, key: Buffer): string {
  const decipher = createDecipheriv(ALGORITHM, key, data.iv);
  decipher.setAuthTag(data.tag);
  return decipher.update(data.ciphertext) + decipher.final("utf-8");
}

// =============================================================================
// File format
// =============================================================================

interface StoreData {
  version: 1;
  secrets: Record<string, string>;
}

function encode(data: StoreData, key: Buffer): Buffer {
  const plaintext = JSON.stringify(data);
  const { iv, tag, ciphertext } = encrypt(plaintext, key);
  return Buffer.concat([iv, tag, ciphertext]);
}

function decode(buffer: Buffer, key: Buffer): StoreData {
  if (buffer.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error("File too short — corrupt or not a secret store");
  }
  const iv = buffer.subarray(0, IV_LENGTH);
  const tag = buffer.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = buffer.subarray(IV_LENGTH + TAG_LENGTH);
  const plaintext = decrypt({ iv, tag, ciphertext }, key);
  return JSON.parse(plaintext) as StoreData;
}

// =============================================================================
// Backend
// =============================================================================

export class EncryptedFileBackend implements SecretBackend {
  readonly name = "encrypted-file";
  private readonly filePath: string;
  private readonly fileMode: number;
  private saltPath: string;
  private salt: Buffer | null = null;

  constructor(options?: { storePath?: string; fileMode?: number }) {
    this.filePath = options?.storePath ?? DEFAULT_PATH;
    this.fileMode = options?.fileMode ?? 0o600;
    this.saltPath = this.filePath + ".salt";
  }

  async isAvailable(): Promise<boolean> {
    // crypto is always available in Node.js
    return true;
  }

  // ===========================================================================
  // Key Management
  // ===========================================================================

  private async getOrCreateSalt(): Promise<Buffer> {
    if (this.salt) return this.salt;

    try {
      this.salt = await readFile(this.saltPath);
      return this.salt;
    } catch {
      // Generate a new salt
      this.salt = randomBytes(16);
      const dir = dirname(this.saltPath);
      if (!existsSync(dir)) {
        await mkdir(dir, { recursive: true, mode: 0o700 });
      }
      await writeFile(this.saltPath, this.salt, { mode: this.fileMode });
      return this.salt;
    }
  }

  private async getKey(): Promise<Buffer> {
    const salt = await this.getOrCreateSalt();
    return deriveKey(salt);
  }

  // ===========================================================================
  // Store Operations
  // ===========================================================================

  async get(key: string): Promise<string | undefined> {
    const data = await this.readStore();
    return data.secrets[key];
  }

  async set(key: string, value: string): Promise<void> {
    const data = await this.readStore();
    data.secrets[key] = value;
    await this.writeStore(data);
  }

  async delete(key: string): Promise<boolean> {
    const data = await this.readStore();
    if (!(key in data.secrets)) return false;
    delete data.secrets[key];
    await this.writeStore(data);
    return true;
  }

  async list(): Promise<string[]> {
    const data = await this.readStore();
    return Object.keys(data.secrets);
  }

  // ===========================================================================
  // Persistence
  // ===========================================================================

  private async readStore(): Promise<StoreData> {
    try {
      const raw = await readFile(this.filePath);
      const key = await this.getKey();
      return decode(raw, key);
    } catch {
      return { version: 1, secrets: {} };
    }
  }

  private async writeStore(data: StoreData): Promise<void> {
    const key = await this.getKey();
    const encoded = encode(data, key);
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true, mode: 0o700 });
    }
    await writeFile(this.filePath, encoded, { mode: this.fileMode });
  }
}
