/**
 * SecretServiceBackend — Linux Secret Service (libsecret) via secret-tool CLI.
 *
 * Uses the freedesktop.org Secret Service through the `secret-tool` command
 * (part of libsecret-tools package). Stores secrets with attributes
 * { application: "secret-store", key: "<key>" } for individual lookup and clear.
 *
 * KEY INDEX: Because some Secret Service implementations (notably KDE's
 * ksecretd) return incomplete results from `search` when multiple items share
 * the same attribute, we maintain a separate key-index item stored under the
 * reserved key `__keys__` as a JSON-serialized array. This index is updated
 * on every set() and delete(), and list() reads it directly via lookup().
 *
 * Requires: secret-tool (libsecret-tools)
 *   Debian/Ubuntu: sudo apt install libsecret-tools
 *   Fedora: sudo dnf install libsecret-tools
 *   Arch: sudo pacman -S libsecret
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { SecretBackend } from "./interface.js";

const execFileAsync = promisify(execFile);

/** Escape a string for single-quoted shell usage */
function shq(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

// =============================================================================
// Constants
// =============================================================================

const TOOL = "secret-tool";
const APP_LABEL = "secret-store";
const KEY_INDEX_KEY = "__keys__";

/** Build a shell command for `secret-tool store` with value piped via stdin */
function storeCommand(key: string, value: string): string {
  const label = `secret-store/${key}`;
  return `echo ${shq(value)} | secret-tool store --label ${shq(label)} application ${APP_LABEL} key ${shq(key)}`;
}

/** Attribute pairs for `secret-tool lookup` / `clear` */
function searchArgs(key: string): string[] {
  return ["application", APP_LABEL, "key", key];
}

// =============================================================================
// Backend
// =============================================================================

export class SecretServiceBackend implements SecretBackend {
  readonly name = "secret-service";

  async isAvailable(): Promise<boolean> {
    try {
      const { stdout } = await execFileAsync("which", [TOOL]);
      return stdout.trim().length > 0;
    } catch {
      return false;
    }
  }

  async get(key: string): Promise<string | undefined> {
    try {
      const { stdout } = await execFileAsync(TOOL, ["lookup", ...searchArgs(key)]);
      return stdout.replace(/\n$/, "") || undefined;
    } catch {
      return undefined;
    }
  }

  async set(key: string, value: string): Promise<void> {
    // Store the secret value
    await execFileAsync("sh", ["-c", storeCommand(key, value)]);
    // Update the key index (add this key if not already present)
    await this.updateIndex((keys) => {
      if (!keys.includes(key)) keys.push(key);
    });
  }

  async delete(key: string): Promise<boolean> {
    try {
      await execFileAsync(TOOL, ["clear", ...searchArgs(key)]);
      // Update the key index (remove this key)
      await this.updateIndex((keys) => {
        const idx = keys.indexOf(key);
        if (idx !== -1) keys.splice(idx, 1);
      });
      return true;
    } catch {
      return false;
    }
  }

  async list(): Promise<string[]> {
    try {
      // Read the key index stored under the reserved key
      const raw = await this.get(KEY_INDEX_KEY);
      if (!raw) return [];
      const keys = JSON.parse(raw) as string[];
      return Array.isArray(keys) ? keys : [];
    } catch {
      return [];
    }
  }

  // ===========================================================================
  // Key Index Management
  // ===========================================================================

  /**
   * Read the current key index, apply a mutation, then write it back.
   * Creates the index if it doesn't exist.
   */
  private async updateIndex(mutate: (keys: string[]) => void): Promise<void> {
    try {
      const raw = await this.get(KEY_INDEX_KEY);
      const keys: string[] = raw ? (JSON.parse(raw) as string[]) : [];
      mutate(keys);
      // Write the updated index back using shell pipe (same as set)
      const value = JSON.stringify(keys);
      await execFileAsync("sh", ["-c", storeCommand(KEY_INDEX_KEY, value)]);
    } catch (e) {
      console.error(`[secret-store] Failed to update key index:`, e);
    }
  }
}
