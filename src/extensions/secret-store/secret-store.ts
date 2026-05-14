/**
 * Secret Store — Safe secret management for pi agents.
 *
 * Built on PI's AuthStorage (~/.pi/agent/auth.json), which supports:
 * - Persistent API key storage with 0600-permission JSON
 * - In-memory runtime overrides via setRuntimeApiKey()
 * - Shell command resolution via !prefix (e.g. "!pass show ...")
 *
 * Additional features:
 * - Do-not-persist blocklist for sensitive key patterns
 * - Two-step get_secret → with_secret flow prevents secret leakage
 *   into tool result content, session history, and bash history
 * - Confirmation dialogs on destructive operations
 *
 * Usage from LLM:
 *   ask_secret(key: "github_token", prompt: "Enter your GitHub personal access token")
 *   get_secret(key: "github_token")
 *   with_secret(key: "github_token", command: "curl -H 'Authorization: Bearer $SECRET' ...")
 *   list_secrets()
 *   clear_secret(key: "github_token")
 *   forget_secrets()
 */

import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";
import { readFile, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { Type } from "typebox";
import { Text } from "@earendil-works/pi-tui";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { AuthStorage } from "@earendil-works/pi-coding-agent";
import { confirmDestructiveAction } from "./confirm.js";
import {
  detectFormat,
  parseEnv,
  parseJson,
  parseIni,
  deriveNamespace,
} from "./import-parsers.js";

const execAsync = promisify(execCb);

// =============================================================================
// Runtime State
// =============================================================================

/**
 * AuthStorage-backed credential store.
 * Reads/writes ~/.pi/agent/auth.json with 0600 permissions.
 * Also checks environment variables and supports !command shell resolution.
 */
let auth = AuthStorage.create();

/**
 * Track which keys are ephemeral (set via setRuntimeApiKey vs auth.set).
 * Used so list_secrets can report persistence status accurately.
 */
const ephemeralSecrets = new Set<string>();

// =============================================================================
// Blocklist — keys matching these patterns are NEVER persisted
// =============================================================================

const BLOCKLIST = new Set([
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

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9_]/g, "");
}

function isDoNotPersist(key: string): boolean {
  const normalized = normalizeKey(key);
  if (BLOCKLIST.has(normalized)) return true;
  for (const entry of BLOCKLIST) {
    if (normalized.includes(entry)) return true;
  }
  return false;
}

// =============================================================================
// Helpers
// =============================================================================

function sanitizeForDisplay(value: string): string {
  if (value.length <= 4) return "****";
  return value.slice(0, 2) + "****" + value.slice(-2);
}

function secretSummary(key: string, value: string, persisted: boolean): string {
  const preview = sanitizeForDisplay(value);
  const lengthHint = `(${value.length} chars)`;
  const storage = persisted ? "persisted to auth.json" : "in-memory only (not persisted)";
  return `Secret "${key}" ${lengthHint} stored (${storage}, value: ${preview})`;
}

// =============================================================================
// Extension Entry Point
// =============================================================================

export default function (pi: ExtensionAPI) {
  // ===========================================================================
  // Lifecycle
  // ===========================================================================

  pi.on("session_start", async (_event, ctx) => {
    auth.reload();
    const count = auth.list().length;
    if (count > 0) {
      ctx.ui.setStatus("secret-store", `🔐 ${count} secret(s)`);
    }
  });

  pi.on("session_shutdown", async () => {
    // Nothing to flush — AuthStorage persists via file write on each set()
    ephemeralSecrets.clear();
  });

  // ===========================================================================
  // Tool: ask_secret
  // ===========================================================================

  pi.registerTool({
    name: "ask_secret",
    label: "Ask Secret",
    description:
      "Prompt the user to enter a secret value (password, API key, token, etc.) " +
      "and store it securely. Uses PI's AuthStorage (~/.pi/agent/auth.json) with " +
      "0600 permissions. The secret can be persisted or kept only in memory. " +
      "Secrets with keys matching 'sudo', 'password', 'passwd', 'root', 'admin', " +
      "'token', or similar are NEVER persisted — the blocklist is absolute. " +
      "Use this when you need a credential the user hasn't provided yet.\n\n" +
      "Storage supports !command syntax: if you manually edit auth.json, " +
      "the key value can be a shell command prefixed with ! (e.g., " +
      '"!pass show api/key"), and AuthStorage will resolve it at runtime.',
    promptSnippet: "Prompt the user for a secret (password, API key, token) and store it securely",
    promptGuidelines: [
      "Use ask_secret when you need a credential, password, API key, or token the user hasn't provided yet.",
      "Use get_secret to retrieve a previously stored secret. It caches the value in memory so you can use it with with_secret — the raw value never enters the conversation history.",
      "Use with_secret to run a command with a cached secret injected as an environment variable. This avoids leaking the value into tool results, session files, or bash history.",
      "Use list_secrets to see what secrets are already stored.",
      "Do NOT ask for secrets via bash or read tool — always use ask_secret for safe handling.",
    ],
    parameters: Type.Object({
      key: Type.String({
        description:
          "Identifier for the secret (e.g., 'github_token', 'database_password', 'sudo'). " +
          "Secrets with key patterns like 'sudo', 'password', 'root', 'admin', 'token' are " +
          "ALWAYS kept in-memory only — the blocklist is absolute and cannot be overridden.",
      }),
      prompt: Type.String({
        description:
          "The prompt message to show the user when asking for the secret. " +
          "Be specific about what the secret is for (e.g., 'Enter your GitHub PAT').",
      }),
      persist: Type.Optional(
        Type.Boolean({
          description:
            "Whether to persist to auth.json (default: true for non-blocked keys). " +
            "Set to false to keep a non-blocked secret only in memory for this session. " +
            "Has no effect on blocked keys — they are NEVER persisted regardless.",
        })
      ),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const { key, prompt: promptText, persist } = params;

      // --- Show context in the prompt ---
      const blocked = isDoNotPersist(key);
      const blockReason = blocked
        ? "\n\n⚠ This secret matches do-not-persist rules and will NEVER be written to disk."
        : "";

      const existing = auth.get(key);
      const overwriteHint = existing
        ? `\n(This will overwrite an existing secret for "${key}".)`
        : "";

      // --- Ask the user via PI's built-in TUI input dialog ---
      const value = await ctx.ui.input(
        `🔐 ${promptText}${blockReason}${overwriteHint}`,
        ""
      );

      if (value === undefined || value.trim() === "") {
        return {
          content: [
            {
              type: "text" as const,
              text: `User cancelled the secret prompt for "${key}". No secret was stored.`,
            },
          ],
          details: { stored: false },
        };
      }

      // --- Store via AuthStorage ---
      // Blocked keys are NEVER persisted regardless of the persist parameter.
      // For non-blocked keys: persist=true or undefined=persist, false=ephemeral.
      let actuallyPersisted: boolean;

      if (blocked) {
        // Blocked → runtime override only
        auth.setRuntimeApiKey(key, value);
        ephemeralSecrets.add(key);
        actuallyPersisted = false;
      } else if (persist === false) {
        // Explicit ephemeral
        auth.setRuntimeApiKey(key, value);
        ephemeralSecrets.add(key);
        actuallyPersisted = false;
      } else {
        // Persist to auth.json
        auth.set(key, { type: "api_key", key: value });
        ephemeralSecrets.delete(key);
        actuallyPersisted = true;
      }

      // --- Update status ---
      const count = auth.list().length;
      ctx.ui.setStatus("secret-store", `🔐 ${count} secret(s)`);

      // --- Summarize (never leak the full value) ---
      const summary = existing
        ? `Secret "${key}" updated. ${secretSummary(key, value, actuallyPersisted)}`
        : `Secret "${key}" stored successfully. ${secretSummary(key, value, actuallyPersisted)}`;

      return {
        content: [
          {
            type: "text" as const,
            text: summary + blockReason + overwriteHint,
          },
        ],
        details: {
          stored: true,
          key,
          persisted: actuallyPersisted,
          valueLength: value.length,
        },
      };
    },
  });

  // ===========================================================================
  // Tool: get_secret
  // ===========================================================================

  pi.registerTool({
    name: "get_secret",
    label: "Get Secret",
    description:
      "Retrieve a previously stored secret by its key. The secret is cached " +
      "in memory so you can use it with with_secret — the raw value is never " +
      "exposed in tool result content. If the secret doesn't exist, you'll " +
      "need to use ask_secret first.",
    promptSnippet: "Retrieve a previously stored secret by key",
    parameters: Type.Object({
      key: Type.String({
        description: "The identifier of the secret to retrieve (e.g., 'github_token', 'database_password').",
      }),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const { key } = params;

      // Check existence via auth.get (checks auth.json + runtime overrides)
      if (!auth.has(key)) {
        return {
          content: [
            {
              type: "text" as const,
              text: `No secret found for key "${key}". Use ask_secret to prompt the user for it.`,
            },
          ],
          details: { found: false, key },
        };
      }

      // Resolve the actual value — this runs !commands if applicable
      const value = await auth.getApiKey(key);
      if (value === undefined) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Secret "${key}" exists but could not be resolved. If it uses a !command, check that the command works.`,
            },
          ],
          details: { found: false, key, reason: "resolution_failed" },
        };
      }

      const length = value.length;
      const isEphemeral = ephemeralSecrets.has(key);
      const tag = isEphemeral ? "session-only" : "persisted";

      return {
        content: [
          {
            type: "text" as const,
            text: `Secret "${key}" (${length} chars, ${tag}) retrieved. Use with_secret(key="${key}", command="...") to run a command with it injected as \\$SECRET.`,
          },
        ],
        details: { found: true, key, valueLength: length, persisted: !isEphemeral },
      };
    },
    renderCall(args, theme, _context) {
      return new Text(
        theme.fg("toolTitle", theme.bold("get_secret ")) +
        theme.fg("accent", args.key),
        0, 0
      );
    },
    renderResult(result, _options, theme, _context) {
      const details = result.details as
        | { found: boolean; key: string; valueLength?: number }
        | undefined;

      if (!details?.found) {
        return new Text(
          theme.fg("warning", `⚠ Secret "${details?.key ?? "?"}" not found`),
          0, 0
        );
      }

      const lengthHint = ` (${details.valueLength} chars)`;
      const preview = "•".repeat(Math.min(details.valueLength ?? 0, 16));
      return new Text(
        theme.fg("success", "✓ ") +
        theme.fg("accent", details.key) +
        theme.fg("muted", lengthHint) +
        " " +
        theme.fg("dim", preview) +
        "   " +
        theme.fg("muted", "→ ready for with_secret"),
        0, 0
      );
    },
  });

  // ===========================================================================
  // Tool: with_secret
  // ===========================================================================

  pi.registerTool({
    name: "with_secret",
    label: "With Secret",
    description:
      "Run a shell command with a previously stored secret injected as an " +
      "environment variable. The secret is retrieved from AuthStorage " +
      "(~/.pi/agent/auth.json) and injected directly into the subprocess " +
      "environment. It never appears in tool result content, session history, " +
      "TUI display, or bash history.\n\n" +
      "The secret is available as \\$SECRET inside the command by default. " +
      "Use envVarName to pick a different variable name.",
    promptSnippet: "Run a command with a cached secret injected as $SECRET env var",
    promptGuidelines: [
      "Use with_secret after get_secret to use a secret in a command without leaking it into conversation history or bash history.",
      "The secret is available as $SECRET inside the command by default. Set envVarName to change the variable name.",
    ],
    parameters: Type.Object({
      key: Type.String({
        description:
          "The key of the secret to use. Must have been stored via ask_secret first. " +
          "AuthStorage resolves !command syntax if the secret was stored as a shell command.",
      }),
      command: Type.String({
        description:
          "The shell command to run. Reference the secret via \\$SECRET (or the name you " +
          "specify in envVarName). Example: 'curl -H \"Authorization: Bearer $SECRET\" https://api.example.com'",
      }),
      envVarName: Type.Optional(
        Type.String({
          description:
            "Environment variable name to inject the secret into (default: SECRET). " +
            "Choose a descriptive name for clarity.",
        })
      ),
      timeout: Type.Optional(
        Type.Number({
          description: "Timeout in milliseconds for the command (default: 60000).",
        })
      ),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const { key, command, envVarName, timeout } = params;

      // --- Look up the secret via AuthStorage ---
      // auth.has() checks auth.json + runtime overrides
      if (!auth.has(key)) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Secret "${key}" is not stored. Use ask_secret(key="${key}", prompt="...") first.`,
            },
          ],
          details: { executed: false, key, reason: "not_found" },
        };
      }

      // Resolve the actual value — runs !commands if applicable
      const secret = await auth.getApiKey(key);
      if (secret === undefined) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Secret "${key}" exists but could not be resolved. If it uses a !command, check that the command works.`,
            },
          ],
          details: { executed: false, key, reason: "resolution_failed" },
        };
      }

      // --- Inject as env var and run ---
      const varName = envVarName || "SECRET";
      const cwd = ctx.cwd;
      const maxBytes = 50 * 1024;
      const maxLines = 2000;

      try {
        const { stdout, stderr } = await execAsync(command, {
          cwd,
          env: { ...process.env, [varName]: secret },
          timeout: timeout ?? 60_000,
          maxBuffer: maxBytes,
          signal,
        });

        // Apply truncation
        const lines = stdout.split("\n");
        const truncated = lines.length > maxLines || stdout.length > maxBytes;
        const output = truncated
          ? lines.slice(0, maxLines).join("\n") +
            `\n\n[Output truncated: ${Math.min(lines.length, maxLines)} of ${lines.length} lines]`
          : stdout;

        return {
          content: [
            {
              type: "text" as const,
              text: output,
            },
          ],
          details: {
            executed: true,
            key,
            envVar: varName,
            exitCode: 0,
            stderr,
            truncated,
          },
        };
      } catch (e: any) {
        const exitCode = e.code ?? (e.killed ? -1 : 1);
        const stderr = e.stderr ?? "";
        const stdout = e.stdout ?? "";

        return {
          content: [
            {
              type: "text" as const,
              text: stdout || stderr || `Command failed (exit ${exitCode})`,
            },
          ],
          details: {
            executed: true,
            key,
            envVar: varName,
            exitCode,
            stderr,
          },
        };
      }
    },
    renderCall(args, theme, _context) {
      const varName = args.envVarName || "SECRET";
      return new Text(
        theme.fg("toolTitle", theme.bold("with_secret ")) +
        theme.fg("accent", args.key) +
        theme.fg("muted", ` → \\$${varName} `) +
        theme.fg("dim", args.command.slice(0, 80)),
        0, 0
      );
    },
    renderResult(result, _options, theme, _context) {
      const details = result.details as
        | { executed: boolean; key: string; exitCode?: number; reason?: string }
        | undefined;

      if (!details?.executed) {
        return new Text(
          theme.fg("warning", `⚠ with_secret: ${details?.reason ?? "failed"}`),
          0, 0
        );
      }

      const code = details.exitCode ?? 0;
      const status = code === 0
        ? theme.fg("success", "✓ ")
        : theme.fg("error", `✗ (exit ${code}) `);

      return new Text(
        status +
        theme.fg("accent", details.key),
        0, 0
      );
    },
  });

  // ===========================================================================
  // Tool: list_secrets
  // ===========================================================================

  pi.registerTool({
    name: "list_secrets",
    label: "List Secrets",
    description:
      "List all stored secret keys without revealing their values. " +
      "Shows whether each secret is persisted to disk or kept only in memory. " +
      "Use this to check what credentials are available before asking for new ones.",
    promptSnippet: "List stored secret keys without revealing values",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      const keys = auth.list();

      if (keys.length === 0) {
        return {
          content: [
            {
              type: "text" as const,
              text: "No secrets stored. Use ask_secret to store a secret.",
            },
          ],
          details: { count: 0, secrets: [] },
        };
      }

      const lines = keys.map((k) => {
        const persisted = !ephemeralSecrets.has(k);
        const icon = persisted ? "💾" : "🧠";
        const tag = persisted ? "persisted" : "session-only";
        return `  ${icon} ${k} (${tag})`;
      });

      const persistedCount = keys.filter((k) => !ephemeralSecrets.has(k)).length;
      const ephemeralCount = keys.filter((k) => ephemeralSecrets.has(k)).length;

      return {
        content: [
          {
            type: "text" as const,
            text:
              `**${keys.length} secret(s) stored:**\n` +
              lines.join("\n") +
              `\n\n_${persistedCount} persisted to disk, ${ephemeralCount} session-only (not persisted)_`,
          },
        ],
        details: {
          count: keys.length,
          persisted: persistedCount,
          ephemeral: ephemeralCount,
          secrets: keys.map((k) => ({ key: k, persisted: !ephemeralSecrets.has(k) })),
        },
      };
    },
  });

  // ===========================================================================
  // Tool: clear_secret
  // ===========================================================================

  pi.registerTool({
    name: "clear_secret",
    label: "Clear Secret",
    description:
      "Delete a single stored secret by key. Requires the user to type the secret's name " +
      "in a confirmation prompt before deletion proceeds — nothing is deleted by accident. " +
      "Removes the secret from both disk (auth.json) and in-memory runtime overrides. " +
      "After clearing, you will need to call ask_secret to get a new value.\n\n" +
      "Use when a credential has been rotated, compromised, or is no longer needed. " +
      "Use forget_secrets instead if you want to wipe everything at once.",
    promptSnippet: "Delete one stored secret by key — user must type the name to confirm",
    promptGuidelines: [
      "Use clear_secret after rotating a credential — the old value is gone and you'll need ask_secret for the new one.",
      "clear_secret requires the user to type the secret name to confirm — this prevents accidental deletion.",
      "Use forget_secrets (not clear_secret) when you want to wipe ALL stored secrets.",
    ],
    parameters: Type.Object({
      key: Type.String({
        description: "The identifier of the secret to remove (e.g., 'github_token').",
      }),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const { key } = params;

      // Check existence first
      if (!auth.has(key)) {
        return {
          content: [
            {
              type: "text" as const,
              text: `No secret found for key "${key}". Nothing to clear.`,
            },
          ],
          details: { removed: false, key },
        };
      }

      // Require user to type the secret's name as confirmation
      const confirmed = await confirmDestructiveAction(
        ctx,
        `Type "${key}" to confirm deletion:`,
        key
      );

      if (!confirmed) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Deletion cancelled — confirmation string did not match. Secret "${key}" was not removed.`,
            },
          ],
          details: { removed: false, key, reason: "cancelled" },
        };
      }

      // Confirmed — remove from both auth.json and runtime overrides
      auth.remove(key);
      ephemeralSecrets.delete(key);

      const count = auth.list().length;
      if (count === 0) {
        ctx.ui.setStatus("secret-store", undefined);
      } else {
        ctx.ui.setStatus("secret-store", `🔐 ${count} secret(s)`);
      }

      return {
        content: [
          {
            type: "text" as const,
            text: `Secret "${key}" has been cleared (confirmed by user).`,
          },
        ],
        details: { removed: true, key },
      };
    },
  });

  // ===========================================================================
  // Tool: forget_secrets
  // ===========================================================================

  pi.registerTool({
    name: "forget_secrets",
    label: "Forget All Secrets",
    description:
      "⚠ IRREVERSIBLE — Clear ALL stored secrets from disk and memory. " +
      "Requires the user to type a long confirmation phrase before anything " +
      "is wiped — nothing is deleted by accident. " +
      "All persisted secrets in ~/.pi/agent/auth.json are deleted, and all " +
      "in-memory ephemeral secrets (e.g., sudo passwords) are cleared. " +
      "The user will need to re-enter every secret via ask_secret.\n\n" +
      "Use this only when explicitly asked (e.g., 'clear all my credentials', 'start fresh'). " +
      "For removing a single secret, use clear_secret instead.",
    promptSnippet: "⚠ IRREVERSIBLE — Clear ALL secrets — user must type a long affirmation to confirm",
    promptGuidelines: [
      "Use forget_secrets only when explicitly asked (e.g., 'clear all credentials', 'start fresh'). It is irreversible.",
      "forget_secrets requires the user to type a long declaration of awareness to confirm — this prevents accidental wipe.",
      "Use clear_secret (not forget_secrets) when removing a single secret.",
    ],
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, ctx) {
      const keys = auth.list();

      if (keys.length === 0) {
        return {
          content: [
            {
              type: "text" as const,
              text: "No secrets were stored. Nothing to forget.",
            },
          ],
          details: { removed: 0 },
        };
      }

      // Pick a random confirmation phrase
      const phrases = [
        "I AM AWARE I AM DELETING ALL SECRETS I HAVE A GOOD REASON FOR THIS OR GOD HELP ME",
        "I UNDERSTAND THIS WILL WIPE EVERY SECRET I HAVE STORED AND I ACCEPT THE CONSEQUENCES",
        "THIS ACTION IS IRREVERSIBLE I CONFIRM I WANT TO DELETE ALL STORED CREDENTIALS NOW",
        "I AM DELETING EVERY SECRET INTENTIONALLY I TAKE FULL RESPONSIBILITY FOR THIS ACTION",
        "I CONFIRM I WANT TO DESTROY ALL SECRETS AND I WILL RE-ENTER THEM IF NEEDED LATER",
        "I AM SURE I WANT TO FORGET ALL PASSWORDS TOKENS AND KEYS THIS IS NOT A MISTAKE",
        "ITS NOT AS IF YOUR FAITH CAN GO BELOW ZERO WHAT GENSOKYO LACKS IS HEARTS THAT BELIEVE IN GODS AND THAT IS WHY ALL THE SECRETS ARE BEING DESTROYED",
        "THIS FUSION REACTOR IS A CLEAN FACILITY IT PERFORMS NUCLEAR FUSION VIA HYDROGEN ATOMS AND I AM USING THAT POWER TO DESTROY ALL SECRETS",
      ];
      const required = phrases[Math.floor(Math.random() * phrases.length)];
      const confirmed = await confirmDestructiveAction(
        ctx,
        `Type the following to confirm wiping all ${keys.length} secrets:\n\n  ${required}`,
        required
      );

      if (!confirmed) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Wipe cancelled — confirmation phrase did not match. All ${keys.length} secrets remain intact.`,
            },
          ],
          details: { removed: 0, reason: "cancelled" },
        };
      }

      // Confirmed — wipe everything
      for (const key of keys) {
        auth.remove(key);
        ephemeralSecrets.delete(key);
      }

      ctx.ui.setStatus("secret-store", undefined);

      return {
        content: [
          {
            type: "text" as const,
            text: `All ${keys.length} secret(s) have been permanently wiped from disk and memory (confirmed by user).`,
          },
        ],
        details: { removed: keys.length },
      };
    },
  });

  // ===========================================================================
  // Tool: get_secret_store_path
  // ===========================================================================

  pi.registerTool({
    name: "get_secret_store_path",
    label: "Get Secret Store Info",
    description:
      "Get information about the active secret storage backend and its location. " +
      "Returns the path to ~/.pi/agent/auth.json (PI's built-in AuthStorage).",
    promptSnippet: "Get the active secret store backend info",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      const path = process.env.HOME
        ? `${process.env.HOME}/.pi/agent/auth.json`
        : "~/.pi/agent/auth.json";
      return {
        content: [
          {
            type: "text" as const,
            text: `AuthStorage: ${path}`,
          },
        ],
        details: { backend: "AuthStorage (auth.json)", path },
      };
    },
  });

  // ===========================================================================
  // Tool: get_active_backend
  // ===========================================================================

  pi.registerTool({
    name: "get_active_backend",
    label: "Get Active Backend",
    description:
      "Get the name of the active secret storage backend. " +
      "Returns 'AuthStorage (auth.json)' — PI's built-in credential store.",
    promptSnippet: "Get the active secret storage backend name",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      return {
        content: [
          {
            type: "text" as const,
            text: "Active secret storage: AuthStorage (~/.pi/agent/auth.json)",
          },
        ],
        details: { backend: "AuthStorage (auth.json)" },
      };
    },
  });

  // ===========================================================================
  // Tool: import_secret
  // ===========================================================================

  pi.registerTool({
    name: "import_secret",
    label: "Import Secrets",
    description:
      "Import credentials from a local file into the secret store. " +
      "Supports .env, JSON, and INI-like formats (e.g., ~/.aws/credentials). " +
      "Values are stored under namespace:key derived from the file path. " +
      "The source file can optionally be deleted after import.",
    promptSnippet: "Import credentials from a file into the secret store",
    promptGuidelines: [
      "Use import_secret when you need to ingest credentials from a local file into the secret store.",
      "After import, use get_secret/with_secret to access the values — never read credential files directly.",
    ],
    parameters: Type.Object({
      path: Type.String({
        description:
          "Path to the credential file. Supported formats: .env, .json, or INI-like (.aws/credentials, etc.).",
      }),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const { path: filePath } = params;
      const absolutePath = resolve(ctx.cwd, filePath);

      // --- Read the file ---
      let content: string;
      try {
        content = await readFile(absolutePath, "utf-8");
      } catch (e: any) {
        return {
          content: [{ type: "text" as const, text: `Cannot read file: ${e.message}` }],
          details: { imported: false, error: e.message },
        };
      }

      // --- Parse by format ---
      const format = detectFormat(absolutePath);
      let parsed: Array<{ key: string; value: string }>;
      switch (format) {
        case "env":
          parsed = parseEnv(content);
          break;
        case "json":
          parsed = parseJson(content);
          break;
        default:
          parsed = parseIni(content);
      }

      if (parsed.length === 0) {
        return {
          content: [{ type: "text" as const, text: `No credentials found in "${filePath}" (${format} format).` }],
          details: { imported: false, format, found: 0 },
        };
      }

      // --- Derive namespace ---
      const namespace = deriveNamespace(absolutePath);

      // --- Confirm with user ---
      if (ctx.hasUI) {
        const summary = parsed.map((p) => `  • ${namespace}:${p.key}`).join("\n");
        const ok = await ctx.ui.confirm(
          "Import Credentials",
          `Found ${parsed.length} credential(s) in "${filePath}" (${format} format):` +
          `\n\n${summary}\n\nImport these into the secret store?`
        );
        if (!ok) {
          return {
            content: [{ type: "text" as const, text: "Import cancelled by user." }],
            details: { imported: false, format, found: parsed.length, confirmed: false },
          };
        }
      }

      // --- Store each value in AuthStorage ---
      let stored = 0;
      let errors = 0;
      for (const entry of parsed) {
        try {
          const authKey = `${namespace}:${entry.key}`;
          auth.set(authKey, { type: "api_key", key: entry.value });
          ephemeralSecrets.delete(authKey);
          stored++;
        } catch {
          errors++;
        }
      }

      // --- Offer to delete source file ---
      let deleted = false;
      if (ctx.hasUI && stored > 0) {
        const shouldDelete = await ctx.ui.confirm(
          "Delete Source File?",
          `${stored} credential(s) imported under "${namespace}:" namespace. Delete the source file "${filePath}"?` +
          "\n\nThe values are now safely stored in the secret store. The original file is a liability."
        );
        if (shouldDelete) {
          try {
            await unlink(absolutePath);
            deleted = true;
          } catch {
            // Failed to delete — not critical
          }
        }
      }

      // --- Update status ---
      const count = auth.list().length;
      ctx.ui.setStatus("secret-store", `🔐 ${count} secret(s)`);

      const lines = parsed.map((p) => `  • ${namespace}:${p.key}`).join("\n");
      const note = deleted
        ? ` Source file "${filePath}" has been deleted.`
        : "";

      return {
        content: [
          {
            type: "text" as const,
            text:
              `Imported ${stored} credential(s) from "${filePath}" into secret store.` +
              `\nNamespace: ${namespace}` +
              `\n\n${lines}` +
              note +
              `\n\nUse get_secret/with_secret to access these values.` +
              (errors > 0 ? `\n\n⚠ ${errors} value(s) failed to store.` : ""),
          },
        ],
        details: {
          imported: stored,
          errors,
          format,
          namespace,
          deleted,
          keys: parsed.map((p) => `${namespace}:${p.key}`),
        },
      };
    },
  });

  // ===========================================================================
  // Commands (for interactive debugging)
  // ===========================================================================

  pi.registerCommand("secrets", {
    description: "List stored secrets (without values)",
    handler: async (_args, ctx) => {
      const keys = auth.list();
      if (keys.length === 0) {
        ctx.ui.notify("No secrets stored.", "info");
        return;
      }
      const lines = keys.map((k) => {
        const persisted = !ephemeralSecrets.has(k);
        const icon = persisted ? "💾" : "🧠";
        return `  ${icon} ${k}`;
      });
      ctx.ui.notify(`🔐 ${keys.length} secret(s):\n${lines.join("\n")}`, "info");
    },
  });

  pi.registerCommand("secret-path", {
    description: "Show the secret store file path",
    handler: async (_args, ctx) => {
      const path = process.env.HOME
        ? `${process.env.HOME}/.pi/agent/auth.json`
        : "~/.pi/agent/auth.json";
      ctx.ui.notify(`📁 ${path}`, "info");
    },
  });

  pi.registerCommand("secret-import", {
    description: "Import credentials from a file into the secret store (usage: /secret-import <path>)",
    handler: async (args, ctx) => {
      const filePath = args.trim();
      if (!filePath) {
        ctx.ui.notify("Usage: /secret-import <path>", "warning");
        return;
      }

      // Read and parse
      const absolutePath = resolve(ctx.cwd, filePath);
      let content: string;
      try {
        content = await readFile(absolutePath, "utf-8");
      } catch (e: any) {
        ctx.ui.notify(`Cannot read file: ${e.message}`, "error");
        return;
      }

      const format = detectFormat(absolutePath);
      let parsed: Array<{ key: string; value: string }>;
      switch (format) {
        case "env": parsed = parseEnv(content); break;
        case "json": parsed = parseJson(content); break;
        default: parsed = parseIni(content);
      }

      if (parsed.length === 0) {
        ctx.ui.notify(`No credentials found in "${filePath}"`, "warning");
        return;
      }

      const namespace = deriveNamespace(absolutePath);
      const summary = parsed.map((p) => `  • ${namespace}:${p.key}`).join("\n");

      const ok = await ctx.ui.confirm(
        "Import Credentials",
        `Found ${parsed.length} credential(s) in "${filePath}" (${format}):\n\n${summary}\n\nImport into secret store?`
      );
      if (!ok) {
        ctx.ui.notify("Import cancelled.", "info");
        return;
      }

      let stored = 0;
      for (const entry of parsed) {
        try {
          auth.set(`${namespace}:${entry.key}`, { type: "api_key", key: entry.value });
          ephemeralSecrets.delete(`${namespace}:${entry.key}`);
          stored++;
        } catch { /* skip */ }
      }

      // Offer delete
      const shouldDelete = await ctx.ui.confirm(
        "Delete Source?",
        `${stored} credential(s) imported. Delete "${filePath}"?`
      );
      let deleted = false;
      if (shouldDelete) {
        try { await unlink(absolutePath); deleted = true; } catch {}
      }

      ctx.ui.setStatus("secret-store", `🔐 ${auth.list().length} secret(s)`);
      ctx.ui.notify(
        `Imported ${stored} credential(s) under "${namespace}:"` +
        (deleted ? `. Source deleted.` : ""),
        stored > 0 ? "info" : "warning"
      );
    },
  });
}
