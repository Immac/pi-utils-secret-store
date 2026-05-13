/**
 * Secret Store — pluggable backend secret vault for pi agents.
 *
 * Features:
 * - Pluggable SecretBackend: Secret Service (Linux), Keychain (macOS),
 *   Credential Manager (Windows), or encrypted file (all platforms)
 * - Auto-detects best available backend
 * - In-memory ephemeral secrets for do-not-persist items
 * - Configurable do-not-persist key matchers
 * - Default protection: sudo, password, passwd, root, admin are NEVER persisted
 */

import type { SecretBackend } from "./backends/interface.js";
import { EncryptedFileBackend } from "./backends/file-backend.js";
import { SecretServiceBackend } from "./backends/secret-service-backend.js";
import { MacOSKeychainBackend } from "./backends/macos-keychain-backend.js";
import { WindowsCredentialManagerBackend } from "./backends/windows-credential-manager.js";

// =============================================================================
// Types
// =============================================================================

export interface SecretStoreOptions {
  /**
   * Explicit backend to use. If omitted, auto-detects the best available:
   *   macOS  → Keychain → Encrypted File
   *   Linux  → Secret Service → Encrypted File
   *   Win    → Credential Manager → Encrypted File
   */
  backend?: SecretBackend;
  /**
   * Custom backend chain (ordered by preference).
   * The first available backend in the list wins.
   * If omitted, uses the OS-appropriate defaults.
   */
  backendChain?: SecretBackend[];
  /** Path for the encrypted file backend (default: ~/.pi/agent/secrets.enc) */
  storePath?: string;
  /** Additional keys/patterns that should never be persisted (appended to defaults) */
  doNotPersistKeys?: string[];
  /** Replace the default do-not-persist list entirely instead of appending */
  overrideDoNotPersistKeys?: string[];
  /** File permission mode for file-based backends (default: 0o600) */
  fileMode?: number;
}

// =============================================================================
// Defaults
// =============================================================================

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

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9_]/g, "");
}

function isDoNotPersist(key: string, blocklist: Set<string>): boolean {
  const normalized = normalizeKey(key);
  if (blocklist.has(normalized)) return true;
  for (const entry of blocklist) {
    if (normalized.includes(entry)) return true;
  }
  return false;
}

// =============================================================================
// Backend Auto-Detection
// =============================================================================

/**
 * Build a default backend chain for the current platform.
 * Tries native OS keychain first, falls back to encrypted file.
 */
function defaultBackendChain(options: { storePath?: string; fileMode?: number }): SecretBackend[] {
  const fallback = new EncryptedFileBackend(options);

  if (process.platform === "darwin") {
    return [new MacOSKeychainBackend(), fallback];
  }
  if (process.platform === "win32") {
    return [new WindowsCredentialManagerBackend(), fallback];
  }
  // Linux and everything else
  return [new SecretServiceBackend(), fallback];
}

/**
 * Pick the first available backend from a chain.
 */
async function pickBackend(chain: SecretBackend[]): Promise<SecretBackend> {
  for (const b of chain) {
    try {
      if (await b.isAvailable()) return b;
    } catch {
      // Backend check threw — skip it
    }
  }
  // Last resort: encrypted file is always available
  return chain[chain.length - 1];
}

// =============================================================================
// SecretStore Class
// =============================================================================

export class SecretStore {
  private backend!: SecretBackend;
  private backendChain: SecretBackend[];
  private fileMode: number;
  private blocklist: Set<string>;
  private storePath?: string;

  // In-memory cache of ALL secrets (loaded from backend on load)
  private cache: Map<string, string> = new Map();
  // Ephemeral secrets that should never touch the backend
  private ephemeral: Map<string, string> = new Map();
  // Track what's in the backend vs what's dirty
  private dirty = false;
  private initialised = false;

  constructor(options: SecretStoreOptions = {}) {
    this.fileMode = options.fileMode ?? 0o600;
    this.storePath = options.storePath;

    if (options.overrideDoNotPersistKeys) {
      this.blocklist = new Set(options.overrideDoNotPersistKeys.map(k => normalizeKey(k)));
    } else {
      this.blocklist = new Set(DEFAULT_DO_NOT_PERSIST);
      for (const key of options.doNotPersistKeys ?? []) {
        this.blocklist.add(normalizeKey(key));
      }
    }

    // Backend setup
    const fileOpts = { storePath: options.storePath, fileMode: options.fileMode };
    if (options.backend) {
      // Explicit single backend
      this.backendChain = [options.backend];
    } else if (options.backendChain) {
      // Explicit chain
      this.backendChain = options.backendChain;
    } else {
      // Auto-detect
      this.backendChain = defaultBackendChain(fileOpts);
    }
  }

  // ===========================================================================
  // Initialization
  // ===========================================================================

  /**
   * Initialise the store: pick the best available backend and load secrets.
   * Safe to call multiple times.
   */
  async init(): Promise<void> {
    if (this.initialised) return;

    // If we were given an explicit backend, use it directly
    // Otherwise, auto-detect from the chain
    this.backend = this.backendChain.length === 1
      ? this.backendChain[0]
      : await pickBackend(this.backendChain);

    // Load cached secrets from the backend
    try {
      const keys = await this.backend.list();
      for (const key of keys) {
        const value = await this.backend.get(key);
        if (value !== undefined) {
          this.cache.set(key, value);
        }
      }
    } catch {
      // Backend might be empty or unavailable
    }

    this.initialised = true;
    this.dirty = false;
  }

  /**
   * Get the name of the active backend.
   */
  getBackendName(): string {
    return this.backend?.name ?? "uninitialised";
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
   */
  set(key: string, value: string, persist?: boolean): boolean {
    const blocked = isDoNotPersist(key, this.blocklist);

    if (blocked) {
      this.ephemeral.set(key, value);
      this.cache.delete(key);
      this.dirty = true;
      return false;
    }

    // Non-blocked key: persist to backend
    const shouldPersist = persist !== false;

    if (shouldPersist) {
      this.cache.set(key, value);
      this.ephemeral.delete(key);
    } else {
      this.ephemeral.set(key, value);
      this.cache.delete(key);
    }
    this.dirty = true;

    return shouldPersist;
  }

  /**
   * Retrieve a secret by key.
   * Checks ephemeral store first, then cached store for non-blocked keys.
   */
  get(key: string): string | undefined {
    if (this.ephemeral.has(key)) {
      return this.ephemeral.get(key);
    }
    return this.cache.get(key);
  }

  /**
   * Check if a secret exists.
   */
  has(key: string): boolean {
    return this.ephemeral.has(key) || this.cache.has(key);
  }

  /**
   * Delete a secret from both stores and the backend.
   */
  async delete(key: string): Promise<boolean> {
    const hadEphemeral = this.ephemeral.delete(key);
    const hadCached = this.cache.delete(key);
    if (hadCached || hadEphemeral) {
      this.dirty = true;
      // Also remove from backend
      try {
        await this.backend.delete(key);
      } catch {
        // Ignore backend errors on delete
      }
      this.dirty = false; // backend was updated directly
      return true;
    }
    return false;
  }

  /**
   * List all stored secret keys (without revealing values).
   */
  list(): Array<{ key: string; persisted: boolean }> {
    const keys = new Map<string, boolean>();
    for (const key of this.cache.keys()) {
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
   * Clear all secrets.
   */
  async clear(): Promise<void> {
    // Delete each from backend
    for (const key of this.cache.keys()) {
      try { await this.backend.delete(key); } catch { /* ignore */ }
    }
    this.cache.clear();
    this.ephemeral.clear();
    this.dirty = false;
  }

  // ===========================================================================
  // Persistence
  // ===========================================================================

  /**
   * Flush all cached (non-blocked) secrets to the backend.
   * Call this periodically or on shutdown.
   */
  async flush(): Promise<void> {
    if (!this.dirty || !this.initialised) return;

    // Write all cached keys to backend
    for (const [key, value] of this.cache) {
      try {
        await this.backend.set(key, value);
      } catch (e) {
        console.error(`[secret-store] Failed to flush "${key}":`, e);
      }
    }

    this.dirty = false;
  }

  /**
   * Alias for backward compatibility — calls init() then returns.
   */
  async load(): Promise<void> {
    await this.init();
  }

  /**
   * Alias for backward compatibility — calls flush().
   */
  async save(): Promise<void> {
    await this.flush();
  }

  // ===========================================================================
  // Queries
  // ===========================================================================

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
   * Get the store path for display purposes.
   * Returns the active backend name since there may not be a single file.
   */
  getStorePath(): string {
    return this.backend?.name ?? "uninitialised";
  }
}
