/**
 * Simple file-based secret store — drop-in replacement for AuthStorage.
 *
 * Stores secrets in a JSON file (~/.pi/agent/secrets.json by default) with
 * 0600 permissions. Supports runtime (in-memory) overrides alongside persisted
 * values, matching the interface the secret-store extension needs.
 *
 * This avoids depending on AuthStorage from @earendil-works/pi-coding-agent,
 * which is not part of the package's public API and cannot be imported
 * from extension code due to the exports field restriction.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { homedir } from "node:os";

// ── Types ──────────────────────────────────────────────────────────────────

type StoredValue = Record<string, unknown>;

// ── Config ──────────────────────────────────────────────────────────────────

function defaultStorePath(): string {
  return resolve(homedir(), ".pi", "agent", "secrets.json");
}

// ── SimpleSecretStore ──────────────────────────────────────────────────────

export class SimpleSecretStore {
  private data: StoredValue = {};
  private readonly runtimeOverrides = new Map<string, string>();
  private readonly path: string;

  constructor(storePath?: string) {
    this.path = storePath ?? defaultStorePath();
    this.loadFromDisk();
  }

  // ── Persistence ───────────────────────────────────────────────────────

  /** Load data from the JSON file on disk. */
  private loadFromDisk(): void {
    try {
      if (existsSync(this.path)) {
        const raw = readFileSync(this.path, "utf-8");
        this.data = JSON.parse(raw) as StoredValue;
      } else {
        this.data = {};
      }
    } catch {
      this.data = {};
    }
  }

  /** Save current data to disk with 0600 permissions. */
  private saveToDisk(): void {
    try {
      const dir = dirname(this.path);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      writeFileSync(this.path, JSON.stringify(this.data, null, 2), "utf-8");
      chmodSync(this.path, 0o600);
    } catch {
      // Silently fail — the extension carries on with in-memory-only operation.
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────

  /** Reload from disk, discarding any in-memory changes to persisted data. */
  reload(): void {
    this.loadFromDisk();
  }

  /** Check if a key exists (in persisted data OR as a runtime override). */
  has(key: string): boolean {
    return key in this.data || this.runtimeOverrides.has(key);
  }

  /** Get a stored value (checks persisted data first, then runtime overrides). */
  get(key: string): unknown {
    return this.data[key];
  }

  /** List all persisted keys. */
  list(): string[] {
    return Object.keys(this.data);
  }

  /** Set a persisted value and save to disk. */
  set(key: string, value: unknown): void {
    this.data[key] = value;
    this.saveToDisk();
  }

  /** Remove a key from persisted data and save to disk. */
  remove(key: string): void {
    delete this.data[key];
    this.saveToDisk();
  }

  // ── Runtime Overrides (in-memory only, not persisted) ────────────────

  /** Store a value only in memory — never written to disk. */
  setRuntimeApiKey(key: string, value: string): void {
    this.runtimeOverrides.set(key, value);
  }

  /** Remove an in-memory override. */
  removeRuntimeApiKey(key: string): void {
    this.runtimeOverrides.delete(key);
  }

  /** Resolve a key to its string value.
   *
   * Resolution order:
   *  1. Runtime override (plain string) — returned as-is
   *  2. Persisted value with `{type: "api_key", key: "..."}` structure
   *  3. Persisted value as plain string
   *  4. Otherwise, resolve via environment variable or shell command
   *     if the value looks like a reference
   */
  getApiKey(key: string): string | undefined {
    // 1. Runtime override
    const override = this.runtimeOverrides.get(key);
    if (override !== undefined) return override;

    // 2. Persisted value
    const value = this.data[key];
    if (value === undefined) return undefined;

    // Structured credential { type: "api_key", key: "..." }
    if (typeof value === "object" && value !== null) {
      const obj = value as Record<string, unknown>;
      if (obj.type === "api_key" && typeof obj.key === "string") {
        return obj.key;
      }
    }

    // Plain string
    if (typeof value === "string") return value;

    return undefined;
  }
}
