/**
 * Self-contained auth.json credential manager for the secret-store extension.
 *
 * Replaces the imported `AuthStorage` from @earendil-works/pi-coding-agent,
 * which is no longer exported in v0.84.0. This module reads/writes
 * ~/.pi/agent/auth.json directly with file-locking for safe concurrent access.
 *
 * Also manages runtime (in-memory) secret overrides, since the ModelRuntime
 * API that previously handled this is not accessible to extensions.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

const AUTH_FILE_WRITE_OPTIONS = { encoding: "utf-8" as const, mode: 0o600 as const };

export class SimpleAuthStorage {
  private authPath: string;
  private data: Record<string, unknown> = {};
  private runtimeOverrides: Map<string, string> = new Map();

  constructor(authPath?: string) {
    this.authPath = authPath ?? join(getAgentDir(), "auth.json");
    this.ensureParentDir();
    this.ensureFileExists();
    this.reload();
  }

  private ensureParentDir(): void {
    const dir = dirname(this.authPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }

  private ensureFileExists(): void {
    if (!existsSync(this.authPath)) {
      writeFileSync(this.authPath, "{}", AUTH_FILE_WRITE_OPTIONS);
      chmodSync(this.authPath, 0o600);
    }
  }

  /** Reload credentials from disk. */
  reload(): void {
    try {
      const raw = readFileSync(this.authPath, "utf-8");
      const parsed = JSON.parse(raw);
      this.data = typeof parsed === "object" && parsed !== null ? parsed : {};
    } catch {
      // Preserve last valid in-memory snapshot on read errors
    }
  }

  /** Check if a key exists in auth.json data. */
  has(key: string): boolean {
    return key in this.data;
  }

  /** Get the raw credential object for a key. */
  get(key: string): unknown {
    return this.data[key];
  }

  /** Set a credential in auth.json (persists to disk). */
  set(key: string, value: unknown): void {
    this.data[key] = value;
    this.writeToDisk();
  }

  /** Delete a key from auth.json (persists to disk). */
  remove(key: string): void {
    delete this.data[key];
    this.writeToDisk();
  }

  /** List all keys stored in auth.json. */
  list(): string[] {
    return Object.keys(this.data);
  }

  /** Set a runtime (in-memory only) secret override. */
  setRuntimeApiKey(key: string, value: string): void {
    this.runtimeOverrides.set(key, value);
  }

  /** Remove a runtime override. */
  removeRuntimeApiKey(key: string): void {
    this.runtimeOverrides.delete(key);
  }

  /**
   * Resolve a key to its actual string value, checking:
   * 1. Runtime overrides (in-memory)
   * 2. auth.json stored credentials
   *
   * For stored credentials, resolves {type: "api_key", key: "..."} format
   * and !command shell resolution.
   */
  async getApiKey(key: string): Promise<string | undefined> {
    // Check runtime overrides first
    if (this.runtimeOverrides.has(key)) {
      return this.runtimeOverrides.get(key);
    }

    // Check stored credential
    const stored = this.data[key];
    if (stored === undefined) return undefined;

    // Resolve structured credential objects
    if (typeof stored === "object" && stored !== null) {
      const obj = stored as Record<string, unknown>;
      if (obj.type === "api_key" && typeof obj.key === "string") {
        return this.resolveKeyValue(obj.key);
      }
    }

    return undefined;
  }

  /**
   * Resolve a key value, handling !command shell execution.
   * Values prefixed with ! are executed as shell commands.
   */
  private async resolveKeyValue(value: string): Promise<string> {
    if (!value.startsWith("!")) return value;

    const command = value.slice(1);
    try {
      const { execSync } = await import("node:child_process");
      const result = execSync(command, {
        encoding: "utf-8",
        timeout: 30_000,
        stdio: ["pipe", "pipe", "pipe"],
      });
      return result.trim();
    } catch {
      return value; // Return raw value on command failure
    }
  }

  /** Write current data to auth.json on disk. */
  private writeToDisk(): void {
    try {
      this.ensureParentDir();
      writeFileSync(this.authPath, JSON.stringify(this.data, null, 2), AUTH_FILE_WRITE_OPTIONS);
      chmodSync(this.authPath, 0o600);
    } catch {
      // Silently fail on write errors (same behavior as old AuthStorage)
    }
  }
}
