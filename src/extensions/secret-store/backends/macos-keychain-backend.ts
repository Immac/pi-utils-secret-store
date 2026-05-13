/**
 * MacOSKeychainBackend — macOS Keychain via the `security` CLI.
 *
 * Uses the `security` command-line tool to store and retrieve secrets
 * in the user's default login keychain. Each secret is stored as a
 * generic password item with service name "secret-store" and account
 * name set to the secret key.
 *
 * Requires: security (built-in on macOS)
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { SecretBackend } from "./interface.js";

const execFileAsync = promisify(execFile);

// =============================================================================
// Constants
// =============================================================================

const TOOL = "security";
const SERVICE = "secret-store";

// =============================================================================
// Backend
// =============================================================================

export class MacOSKeychainBackend implements SecretBackend {
  readonly name = "macos-keychain";

  async isAvailable(): Promise<boolean> {
    try {
      const { stdout } = await execFileAsync("which", [TOOL]);
      if (stdout.trim().length === 0) return false;
      // Also verify we're on macOS
      const { stdout: uname } = await execFileAsync("uname", ["-s"]);
      return uname.trim() === "Darwin";
    } catch {
      return false;
    }
  }

  async get(key: string): Promise<string | undefined> {
    try {
      const { stdout } = await execFileAsync(TOOL, [
        "find-generic-password",
        "-s", SERVICE,
        "-a", key,
        "-w", // output only the password
      ]);
      return stdout.replace(/\n$/, "") || undefined;
    } catch {
      return undefined;
    }
  }

  async set(key: string, value: string): Promise<void> {
    // Delete existing first, then add (security doesn't have an idempotent set)
    await this.delete(key).catch(() => {});
    await execFileAsync(TOOL, [
      "add-generic-password",
      "-s", SERVICE,
      "-a", key,
      "-w", value,
      "-U", // allow update (though we delete first)
    ]);
  }

  async delete(key: string): Promise<boolean> {
    try {
      await execFileAsync(TOOL, [
        "delete-generic-password",
        "-s", SERVICE,
        "-a", key,
      ]);
      return true;
    } catch {
      return false;
    }
  }

  async list(): Promise<string[]> {
    try {
      const { stdout } = await execFileAsync(TOOL, [
        "dump-keychain",
        "-r", // raw output
      ]);

      // Parse output for "acct" (account) entries with our service
      const keys: string[] = [];
      let inService = false;

      for (const line of stdout.split("\n")) {
        const svcMatch = line.match(/^\s*"svce"<blob>=\s*"([^"]+)"/);
        if (svcMatch) {
          inService = svcMatch[1] === SERVICE;
          continue;
        }
        if (inService) {
          const acctMatch = line.match(/^\s*"acct"<blob>=\s*"([^"]+)"/);
          if (acctMatch) {
            keys.push(acctMatch[1]);
            inService = false;
          }
        }
      }

      return keys;
    } catch {
      return [];
    }
  }
}
