/**
 * SecretServiceBackend — Linux Secret Service (libsecret) via secret-tool CLI.
 *
 * Uses the freedesktop.org Secret Service through the `secret-tool` command
 * (part of libsecret-tools package). Stores secrets with label "secret-store/<key>"
 * and attributes { application: "secret-store", key: "<key>" } for listing.
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

// =============================================================================
// Constants
// =============================================================================

const TOOL = "secret-tool";
const APP_LABEL = "secret-store";

function attrs(key: string): string[] {
  return [
    "--label=`secret-store/" + key + "`",
    "application", APP_LABEL,
    "key", key,
  ];
}

const LIST_ATTRS = ["application", APP_LABEL];

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
      const { stdout } = await execFileAsync(TOOL, ["lookup", ...attrs(key).slice(1)]);
      return stdout.replace(/\n$/, "") || undefined;
    } catch {
      return undefined;
    }
  }

  async set(key: string, value: string): Promise<void> {
    const args = ["store", ...attrs(key), value];
    await execFileAsync(TOOL, args);
  }

  async delete(key: string): Promise<boolean> {
    try {
      const args = ["delete", ...attrs(key).slice(1)];
      await execFileAsync(TOOL, args);
      return true;
    } catch {
      return false;
    }
  }

  async list(): Promise<string[]> {
    try {
      const args = ["search", ...LIST_ATTRS];
      const { stdout } = await execFileAsync(TOOL, args);

      // Parse secret-tool search output — it lists "key/<value>" lines
      // Format is: key = <value> per attribute, then secret on line by itself
      const keys: string[] = [];
      for (const line of stdout.split("\n")) {
        const match = line.match(/^key\s*=\s*(.+)$/);
        if (match) {
          keys.push(match[1].trim());
        }
      }
      return [...new Set(keys)]; // deduplicate
    } catch {
      return [];
    }
  }
}
