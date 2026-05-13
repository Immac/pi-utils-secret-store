/**
 * Secret Store — safe JSON-backed secret vault for pi agents.
 *
 * Features:
 * - Persists secrets to ~/.pi/agent/secrets.json with 0600 permissions
 * - In-memory ephemeral secrets for do-not-persist items
 * - Configurable do-not-persist key matchers
 * - Default protection: sudo, password, passwd, root, admin are NEVER persisted
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, dirname } from "node:path";

// =============================================================================
// Types
// =============================================================================

export interface SecretStoreOptions {
  /** Path to the secrets JSON file (default: ~/.pi/agent/secrets.json) */
  storePath?: string;
  /** Additional keys/patterns that should never be persisted (appended to defaults) */
  doNotPersistKeys?: string[];
  /** Replace the default do-not-persist list entirely instead of appending */
  overrideDoNotPersistKeys?: string[];
  /** File permission mode for the store file (default: 0o600) */
  fileMode?: number;
}

// =============================================================================
// Defaults
// =============================================================================

const DEFAULT_STORE_PATH = resolve(homedir(), ".pi", "agent", "secrets.json");
const DEFAULT_DO_NOT_PERSIST = new Set([
  "sudo",
  "password",
  "passwd",
  "pass",
  "root",
  "admin",
  "root_password",
  "sudo_password",
  "admin_password",
  "db_password",
  "database_password",
  "pgpass",
  "mysql_password",
  "ssh_key",
  "ssh_key_passphrase",
  "token",
  "access_token",
  "secret_token",
  "api_secret",
]);

// =============================================================================
// Key Match Helpers
// =============================================================================

/**
 * Normalize a secret key to lowercase for matching against do-not-persist rules.
 */
function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9_]/g, "");
}

/**
 * Check if a key should not be persisted.
 * Uses exact match and substring containment against the blocklist.
 */
function isDoNotPersist(key: string, blocklist: Set<string>): boolean {
  const normalized = normalizeKey(key);
  if (blocklist.has(normalized)) return true;
  // Also check if the normalized key contains any blocklist entry
  for (const entry of blocklist) {
    if (normalized.includes(entry)) return true;
  }
  return false;
}

// =============================================================================
// Store Schema
// =============================================================================

interface StoreData {
  version: 1;
  secrets: Record<string, string>;
  created: string;
  updated: string;
}

// =============================================================================
// SecretStore Class
// =============================================================================

export class SecretStore {
  private storePath: string;
  private fileMode: number;
  private blocklist: Set<string>;
  private persisted: Map<string, string> = new Map();
  private ephemeral: Map<string, string> = new Map();
  private loaded = false;
  private dirty = false;

  constructor(options: SecretStoreOptions = {}) {
    this.storePath = options.storePath ?? DEFAULT_STORE_PATH;
    this.fileMode = options.fileMode ?? 0o600;

    if (options.overrideDoNotPersistKeys) {
      this.blocklist = new Set(options.overrideDoNotPersistKeys.map(k => normalizeKey(k)));
    } else {
      this.blocklist = new Set(DEFAULT_DO_NOT_PERSIST);
      for (const key of options.doNotPersistKeys ?? []) {
        this.blocklist.add(normalizeKey(key));
      }
    }
  }

  // ===========================================================================
  // Persistence
  // ===========================================================================

  /**
   * Load persisted secrets from disk.
   * Safe to call multiple times — second load overwrites existing in-memory state.
   */
  async load(): Promise<void> {
    try {
      const raw = await readFile(this.storePath, "utf-8");
      const data = JSON.parse(raw) as StoreData;
      if (data.version === 1 && data.secrets) {
        this.persisted = new Map(Object.entries(data.secrets));
      }
    } catch {
      // File doesn't exist or is corrupt — start fresh
      this.persisted = new Map();
    }
    this.loaded = true;
    this.dirty = false;
  }

  /**
   * Write persisted secrets to disk with secure permissions.
   * Only persists keys that pass the do-not-persist check.
   */
  async save(): Promise<void> {
    if (!this.dirty) return;

    const dir = dirname(this.storePath);
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true, mode: 0o700 });
    }

    // Only persist non-blocked keys
    const persistable: Record<string, string> = {};
    for (const [key, value] of this.persisted) {
      if (!isDoNotPersist(key, this.blocklist)) {
        persistable[key] = value;
      }
    }

    const data: StoreData = {
      version: 1,
      secrets: persistable,
      created: new Date().toISOString(),
      updated: new Date().toISOString(),
    };

    await writeFile(this.storePath, JSON.stringify(data, null, 2), {
      mode: this.fileMode,
      encoding: "utf-8",
    });

    this.dirty = false;
  }

  // ===========================================================================
  // CRUD
  // ===========================================================================

  /**
   * Store a secret.
   *
   * The blocklist is absolute — if a key is blocked it can NEVER be persisted,
   * regardless of the `persist` parameter. The `persist` parameter only affects
   * non-blocked keys: true=persist, false=ephemeral, undefined=persist (default).
   *
   * @param key - The secret identifier.
   * @param value - The secret value.
   * @param persist - For non-blocked keys: true=persist, false=ephemeral, undefined=persist.
   * @returns true if persisted to disk, false if kept only in memory.
   */
  set(key: string, value: string, persist?: boolean): boolean {
    const blocked = isDoNotPersist(key, this.blocklist);

    // Blocked keys can NEVER be persisted — the blocklist is absolute.
    // Persist parameter is only meaningful for non-blocked keys.
    if (blocked) {
      this.ephemeral.set(key, value);
      this.persisted.delete(key);
      this.dirty = true;
      return false;
    }

    // Non-blocked key: respect the persist hint (default: persist)
    const shouldPersist = persist !== false;

    if (shouldPersist) {
      this.persisted.set(key, value);
      this.ephemeral.delete(key);
    } else {
      this.ephemeral.set(key, value);
      this.persisted.delete(key);
    }
    this.dirty = true;

    return shouldPersist;
  }

  /**
   * Retrieve a secret by key.
   * Checks ephemeral store first, then persisted store.
   */
  get(key: string): string | undefined {
    if (this.ephemeral.has(key)) {
      return this.ephemeral.get(key);
    }
    return this.persisted.get(key);
  }

  /**
   * Check if a secret exists.
   */
  has(key: string): boolean {
    return this.ephemeral.has(key) || this.persisted.has(key);
  }

  /**
   * Delete a secret from both stores.
   */
  async delete(key: string): Promise<boolean> {
    const hadEphemeral = this.ephemeral.delete(key);
    const hadPersisted = this.persisted.delete(key);
    if (hadPersisted) this.dirty = true;
    return hadEphemeral || hadPersisted;
  }

  /**
   * List all stored secret keys (without revealing values).
   * Returns { key, persisted } for each secret.
   */
  list(): Array<{ key: string; persisted: boolean }> {
    const keys = new Map<string, boolean>();
    for (const key of this.persisted.keys()) {
      keys.set(key, true);
    }
    for (const key of this.ephemeral.keys()) {
      keys.set(key, false);
    }
    return Array.from(keys.entries()).map(([key, persisted]) => ({
      key,
      persisted,
    }));
  }

  /**
   * Clear all secrets (both persisted and ephemeral).
   */
  async clear(): Promise<void> {
    this.persisted.clear();
    this.ephemeral.clear();
    this.dirty = true;
    await this.save();
  }

  /**
   * Check if a key would be automatically marked as do-not-persist.
   */
  wouldBeBlocked(key: string): boolean {
    return isDoNotPersist(key, this.blocklist);
  }

  /**
   * Get the current blocklist (read-only view).
   */
  getBlocklist(): string[] {
    return Array.from(this.blocklist);
  }

  /**
   * Get the store file path.
   */
  getStorePath(): string {
    return this.storePath;
  }
}
