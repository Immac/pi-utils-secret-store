/**
 * Secret Store — Safe secret management for pi agents.
 *
 * Provides LLM-callable tools to:
 * - Ask the user for secrets (passwords, API keys, tokens) via TUI prompt
 * - Persist secrets to an encrypted (0600-permission) JSON store
 * - Mark secrets as "do not persist" — kept only in memory for the session
 * - Default protection: sudo, password, passwd, root, etc. are NEVER persisted
 *
 * Usage from LLM:
 *   ask_secret(key: "github_token", prompt: "Enter your GitHub personal access token")
 *   get_secret(key: "github_token")
 *   list_secrets()
 *   clear_secret(key: "github_token")
 *   forget_secrets()
 */

import { resolve } from "node:path";
import { homedir } from "node:os";
import { Type } from "typebox";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { SecretStore } from "./store.js";
import { PasswordInput } from "./password-input.js";
import { confirmDestructiveAction } from "./confirm.js";

// =============================================================================
// Runtime State
// =============================================================================

let store = new SecretStore({
  storePath: resolve(homedir(), ".pi", "agent", "secrets.enc"),
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Sanitize a secret value for display — never leak it in logs or error messages.
 */
function sanitizeForDisplay(value: string): string {
  if (value.length <= 4) return "****";
  return value.slice(0, 2) + "****" + value.slice(-2);
}

/**
 * Mask the full secret value from any output content that might be shown to user.
 * Returns a safe summary message with the key, length hint, and sanitized preview.
 */
function secretSummary(key: string, value: string, persisted: boolean): string {
  const preview = sanitizeForDisplay(value);
  const lengthHint = `(${value.length} chars)`;
  const storage = persisted ? "persisted to backend" : "in-memory only (not persisted)";
  return `Secret "${key}" ${lengthHint} stored (${storage}, value: ${preview})`;
}

// =============================================================================
// Extension Entry Point
// =============================================================================

export default function (pi: ExtensionAPI) {
  // ===========================================================================
  // Lifecycle — load persisted secrets on session start
  // ===========================================================================

  pi.on("session_start", async (_event, ctx) => {
    await store.load();
    const count = store.list().length;
    const backend = store.getBackendName();
    if (count > 0) {
      ctx.ui.setStatus("secret-store", `🔐 ${count} secret(s) [${backend}]`);
    }
  });

  pi.on("session_shutdown", async (_event) => {
    await store.save();
  });

  // ===========================================================================
  // Tool: ask_secret
  // ===========================================================================

  pi.registerTool({
    name: "ask_secret",
    label: "Ask Secret",
    description:
      "Prompt the user to enter a secret value (password, API key, token, etc.) " +
      "and store it securely. The secret can be persisted to a safe JSON file " +
      "(~/.pi/agent/secrets.json) or kept only in memory (not persisted). " +
      "Secrets with keys matching 'sudo', 'password', 'passwd', " +
      "'root', 'admin', 'token', or similar are NEVER persisted to disk — " +
      "the blocklist is absolute and cannot be overridden. Use this when you need " +
      "a credential the user hasn't provided yet.",
    promptSnippet: "Prompt the user for a secret (password, API key, token) and store it securely",
    promptGuidelines: [
      "Use ask_secret when you need a credential, password, API key, or token the user hasn't provided yet.",
      "Use get_secret to retrieve a previously stored secret without re-prompting the user.",
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
            "Whether to persist to disk (default: true for non-blocked keys). " +
            "Set to false to keep a non-blocked secret only in memory for this session. " +
            "Has no effect on blocked keys — they are NEVER persisted regardless.",
        })
      ),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const { key, prompt: promptText, persist } = params;

      // --- Show context in the prompt ---
      const blocked = store.wouldBeBlocked(key);
      const blockReason = blocked
        ? "\n\n⚠ This secret matches do-not-persist rules and will NEVER be written to disk."
        : "";

      const existing = store.get(key);
      const overwriteHint = existing
        ? `\n(This will overwrite an existing secret for "${key}".)`
        : "";

      // --- Ask the user (masked input) ---
      let value: string | undefined;

      if (ctx.hasUI) {
        // Use masked custom component in interactive mode
        value = await ctx.ui.custom<string | undefined>(
          (_tui, _theme, _keybindings, done) => {
            const input = new PasswordInput({
              prompt: `🔐 ${promptText}`,
              onSubmit: (v) => done(v),
              onCancel: () => done(undefined),
            });
            return input;
          },
          { overlay: true }
        );
      } else {
        // Fallback for non-interactive / print mode
        value = await ctx.ui.input(
          `🔐 ${promptText}`,
          ""
        );
      }

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

      // --- Store ---
      // Blocked keys are NEVER persisted regardless of the persist parameter.
      // For non-blocked keys: persist=true or undefined=persist, false=ephemeral.
      let actuallyPersisted: boolean;
      if (blocked) {
        actuallyPersisted = store.set(key, value); // persist follows blocklist
      } else {
        actuallyPersisted = store.set(key, value, persist);
      }

      // Save to disk if anything changed
      await store.save();

      // --- Update status ---
      const count = store.list().length;
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
      "Retrieve a previously stored secret by its key. Returns the full secret value " +
      "so you can use it (e.g., as an API key, password for a command). " +
      "If the secret doesn't exist, you'll need to use ask_secret first.",
    promptSnippet: "Retrieve a previously stored secret by key",
    parameters: Type.Object({
      key: Type.String({
        description: "The identifier of the secret to retrieve (e.g., 'github_token', 'database_password').",
      }),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const { key } = params;
      const value = store.get(key);

      if (value === undefined) {
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

      return {
        content: [
          {
            type: "text" as const,
            text: value,
          },
        ],
        details: { found: true, key, valueLength: value.length, persisted: store.list().find(s => s.key === key)?.persisted ?? false },
      };
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
      const secrets = store.list();

      if (secrets.length === 0) {
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

      const lines = secrets.map((s) => {
        const icon = s.persisted ? "💾" : "🧠";
        const tag = s.persisted ? "persisted" : "session-only";
        return `  ${icon} ${s.key} (${tag})`;
      });

      const persistedCount = secrets.filter((s) => s.persisted).length;
      const ephemeralCount = secrets.filter((s) => !s.persisted).length;

      return {
        content: [
          {
            type: "text" as const,
            text:
              `**${secrets.length} secret(s) stored:**\n` +
              lines.join("\n") +
              `\n\n_${persistedCount} persisted to disk, ${ephemeralCount} session-only (not persisted)_`,
          },
        ],
        details: {
          count: secrets.length,
          persisted: persistedCount,
          ephemeral: ephemeralCount,
          secrets: secrets.map((s) => ({ key: s.key, persisted: s.persisted })),
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
      "Removes the secret from both disk (if persisted) and in-memory cache. " +
      "After clearing, you will need to call ask_secret to get a new value. " +
      "\n\nUse when a credential has been rotated, compromised, or is no longer needed. " +
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

      // Check existence first — no need to confirm if nothing to delete
      if (!store.has(key)) {
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

      // Confirmed — proceed with deletion
      await store.delete(key);
      await store.save();

      const count = store.list().length;
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
      "⚠ IRREVERSIBLE — Clear ALL stored secrets from both disk and memory. " +
      "Requires the user to type a long confirmation phrase before anything " +
      "is wiped — nothing is deleted by accident. " +
      "All persisted secrets in ~/.pi/agent/secrets.json are deleted, and all in-memory " +
      "ephemeral secrets (e.g., sudo passwords) are cleared. The user will need to re-enter " +
      "every secret via ask_secret. " +
      "\n\nUse this only when explicitly asked (e.g., 'clear all my credentials', 'start fresh'). " +
      "For removing a single secret, use clear_secret instead.",
    promptSnippet: "⚠ IRREVERSIBLE — Clear ALL secrets — user must type a long affirmation to confirm",
    promptGuidelines: [
      "Use forget_secrets only when explicitly asked (e.g., 'clear all credentials', 'start fresh'). It is irreversible.",
      "forget_secrets requires the user to type a long declaration of awareness to confirm — this prevents accidental wipe.",
      "Use clear_secret (not forget_secrets) when removing a single secret.",
    ],
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, ctx) {
      const count = store.list().length;

      if (count === 0) {
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

      // Pick a random confirmation phrase so muscle memory doesn't help
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
        `Type the following to confirm wiping all ${count} secrets:\n\n  ${required}`,
        required
      );

      if (!confirmed) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Wipe cancelled — confirmation phrase did not match. All ${count} secrets remain intact.`,
            },
          ],
          details: { removed: 0, reason: "cancelled" },
        };
      }

      // Confirmed — wipe everything
      await store.clear();
      ctx.ui.setStatus("secret-store", undefined);

      return {
        content: [
          {
            type: "text" as const,
            text: `All ${count} secret(s) have been permanently wiped from disk and memory (confirmed by user).`,
          },
        ],
        details: { removed: count },
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
      "Returns the name of the active backend (secret-service, macos-keychain, " +
      "windows-credential-manager, or encrypted-file) and any relevant path. " +
      "Useful for debugging which credential store is being used.",
    promptSnippet: "Get the active secret store backend info",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Active backend: ${store.getBackendName()}`,
          },
        ],
        details: { backend: store.getBackendName() },
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
      "Returns one of: secret-service (Linux), macos-keychain (macOS), " +
      "windows-credential-manager (Windows), or encrypted-file (fallback). " +
      "Useful to know where secrets are actually being stored.",
    promptSnippet: "Get the active secret storage backend name",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Active secret storage backend: ${store.getBackendName()}`,
          },
        ],
        details: { backend: store.getBackendName() },
      };
    },
  });

  // ===========================================================================
  // Commands (for interactive debugging)
  // ===========================================================================

  pi.registerCommand("secrets", {
    description: "List stored secrets (without values)",
    handler: async (_args, ctx) => {
      const secrets = store.list();
      if (secrets.length === 0) {
        ctx.ui.notify("No secrets stored.", "info");
        return;
      }
      const lines = secrets.map((s) => {
        const icon = s.persisted ? "💾" : "🧠";
        return `  ${icon} ${s.key}`;
      });
      ctx.ui.notify(`🔐 ${secrets.length} secret(s):\n${lines.join("\n")}`, "info");
    },
  });

  pi.registerCommand("secret-path", {
    description: "Show the secret store file path",
    handler: async (_args, ctx) => {
      ctx.ui.notify(`📁 ${store.getStorePath()}`, "info");
    },
  });
}
