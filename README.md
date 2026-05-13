# 🔐 Secret Store

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=flat-square)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Pi Extension](https://img.shields.io/badge/pi-extension-orange?style=flat-square)](https://github.com/earendil-works/pi-coding-agent)

**Safe secret management for pi agents** — prompt users for secrets (passwords, API keys, tokens), store them securely with optional persistence, and retrieve them on demand. Secrets matching sensitive patterns (sudo, password, root, etc.) are NEVER persisted to disk by default.

---

## Features

| Feature | Tool / Command | What It Does |
|---------|---------------|-------------|
| 🆕 **Ask for a Secret** | `ask_secret` | Prompts the user via TUI dialog, stores the value securely |
| 🔍 **Retrieve a Secret** | `get_secret` | Returns a stored secret value to the LLM |
| 📋 **List Secrets** | `list_secrets` | Shows stored secret keys (without values) + persistence status |
| 🗑️ **Clear a Secret** | `clear_secret` | Deletes a single secret from both disk and memory |
| 🧹 **Forget All** | `forget_secrets` | Clears ALL secrets from disk and memory |
| 📁 **Store Path** | `get_secret_store_path` | Shows the location of the secrets JSON file |
| 🔐 **Status Line** | _(auto)_ | Shows `🔐 N secret(s)` in the footer when secrets exist |
| 📟 **List Command** | `/secrets` | Interactive command to list stored secrets |
| 📟 **Path Command** | `/secret-path` | Interactive command to show the store file path |

### Security Features

- **Safe JSON Store** — secrets persisted to `~/.pi/agent/secrets.json` with `0600` permissions
- **Do-Not-Persist List** — secrets with keys matching sensitive patterns are kept **in-memory only**
- **Default Protection** — `sudo`, `password`, `passwd`, `root`, `admin`, `token`, and related patterns are **never written to disk** — full stop
- **Absolute Blocklist** — the blocklist CANNOT be overridden. Blocked keys are NEVER persisted regardless of the `persist` parameter

### Default Do-Not-Persist Patterns

The following keys (and any key containing these as substrings, case-insensitive) are never persisted:

`sudo`, `password`, `passwd`, `pass`, `root`, `admin`, `root_password`, `sudo_password`, `admin_password`, `db_password`, `database_password`, `pgpass`, `mysql_password`, `ssh_key`, `ssh_key_passphrase`, `token`, `access_token`, `secret_token`, `api_secret`

---

## Quick Start

### For Users

```bash
# From the repository location
pi install /path/to/secret-store

# Or symlink for development
ln -s /path/to/secret-store ~/.pi/agent/packages/secret-store
```

Then reload pi (`/reload`) and the tools are available to the LLM.

### For LLM (Agent) Usage

The LLM calls these tools automatically when it needs credentials. Here's the typical flow:

1. **Agent needs a credential** → calls `ask_secret(key: "github_token", prompt: "Enter your GitHub personal access token:")`
2. **TUI dialog appears** → user types the secret
3. **Secret is stored** → in memory (and optionally persisted to disk)
4. **Agent uses the secret** → calls `get_secret(key: "github_token")` to retrieve it
5. **Done with the secret** → calls `clear_secret(key: "github_token")` to remove it

### Example Prompts (what users say to the LLM)

> "Deploy to production using my GitHub token"

LLM → asks for the token via `ask_secret`, retrieves it with `get_secret`, uses it.

> "What secrets do I have stored?"

LLM → calls `list_secrets` to enumerate stored keys.

> "Clear all my stored credentials"

LLM → calls `forget_secrets` to wipe the store.

---

## Tool API Reference

### `ask_secret`

Prompt the user for a secret and store it securely.

```typescript
interface AskSecretParams {
  key: string;           // Identifier (e.g., "github_token", "database_password", "sudo")
  prompt: string;        // Message shown in the TUI dialog
  persist?: boolean;     // Override persistence behavior (optional)
}
```

**Persistence logic:**
- The blocklist is **absolute** — blocked keys are NEVER persisted regardless of `persist`
- `persist` not set (default) → blocked keys go to memory, non-blocked keys go to disk
- `persist: false` → keep a non-blocked key in memory only (no effect on blocked keys)
- `persist: true` → same as default (only affects non-blocked keys; blocked keys are still blocked)

### `get_secret`

Retrieve a stored secret by key.

```typescript
interface GetSecretParams {
  key: string;  // Secret identifier
}
```

Returns the full secret value if found, or a "not found" message.

### `list_secrets`

List all stored secret keys without revealing values.

```typescript
// No parameters
```

Returns a formatted list with persistence indicators (💾 persisted, 🧠 session-only).

### `clear_secret`

Delete a single secret.

```typescript
interface ClearSecretParams {
  key: string;  // Secret identifier to remove
}
```

### `forget_secrets`

Clear ALL secrets from disk and memory.

```typescript
// No parameters
```

### `get_secret_store_path`

Get the filesystem path of the secret store JSON file.

```typescript
// No parameters
```

---

## Commands

| Command | Description |
|---------|-------------|
| `/secrets` | List all stored secret keys (without values) |
| `/secret-path` | Show the secret store file path |

---

## Development

```bash
# Validate TypeScript
npm run validate

# Run tests
npm test

# Run all
npm test && npm run validate
```

### Project Structure

```
secret-store/
├── package.json                              # pi.extensions entrypoint
├── tsconfig.json
├── .gitignore
├── src/extensions/secret-store/
│   ├── secret-store.ts                       # Main extension: tools, commands, lifecycle
│   └── store.ts                              # SecretStore class (CRUD, persistence, blocklist)
├── test/
│   └── secret-store.test.ts                  # 28+ tests covering CRUD, blocklist, persistence, edge cases
└── README.md
```

---

## Architecture

```
LLM calls ask_secret("github_token", "Enter token:")
            │
            ▼
    secret-store extension
            │
    ┌───────┴───────┐
    │  ctx.ui.input() │  ← Prompts user via TUI dialog
    └───────┬───────┘
            │
            ▼
    SecretStore.set(key, value, persist?)
            │
    ┌───────┴─────────────────┐
    │                         │
    ▼                         ▼
  In-Memory Map            ~/.pi/agent/secrets.json
  (ephemeral)               (0600 permissions)
                            (blocked keys filtered out)
```

The `SecretStore` class is the core engine. It maintains two separate Maps:
- **`persisted`** — keys that survive restarts (written to `secrets.json`)
- **`ephemeral`** — keys that live only for the current session

On `session_start`, the store loads from disk. On `session_shutdown`, it saves. Between those events, the store is the single source of truth.

---

## Security Notes

- The secrets JSON file uses **0600 permissions** (owner read/write only)
- The directory `~/.pi/agent/` is created with **0700 permissions** if it doesn't exist
- Secrets are never logged or included in error messages
- The `list_secrets` tool reveals **keys only**, never values
- The `ask_secret` return value shows a sanitized preview (first 2 + last 2 chars) — never the full value
- The blocklist is **case-insensitive** and uses substring matching for broad coverage

**⚠️ Limitations:**
- The JSON file is **not encrypted at rest** — it relies on filesystem permissions (0600)
- For production use, consider encrypting the store or using a dedicated secret manager
- In interactive mode, the `ask_secret` tool uses a **masked custom TUI component** (`PasswordInput`) — all typed characters display as `•` so the secret is never visible on screen
- In non-interactive mode (print/JSON), `ask_secret` falls back to `ctx.ui.input()` which does not mask

---

## License

MIT
