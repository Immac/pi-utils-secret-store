# 🔐 Secret Store

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=flat-square)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Pi Extension](https://img.shields.io/badge/pi-extension-orange?style=flat-square)](https://github.com/earendil-works/pi-coding-agent)

**LLM-safe secret management for pi agents.** A tool UX layer on top of PI's built-in `AuthStorage` (`~/.pi/agent/auth.json`) that lets the LLM securely prompt for, retrieve, list, and manage secrets — without leaking them into conversation history.

---

## Motivation

PI already has a credential store (`AuthStorage` at `~/.pi/agent/auth.json`). It supports:

- API key persistence with `0600` perms
- Shell command resolution (`!pass show ...`, `!op read ...`)
- Runtime overrides (`setRuntimeApiKey`)
- OAuth tokens via `/login`

But `AuthStorage` is a **developer API** — the LLM can't call it directly. If the LLM needs a password, it has no way to ask you for one, or to use it without the value ending up visible in tool results, session history, and compaction summaries.

**This extension bridges that gap.** It wraps `AuthStorage` with LLM-callable tools that enforce safe handling of secrets:

- 🗣️ **Ask** via TUI dialog (paste-friendly `ctx.ui.input()`)
- 🔒 **Retrieve** without leaking to `content` (two-step `get_secret` → `with_secret`)
- 🚫 **Blocklist** prevents accidental persistence of sensitive key patterns
- 🔐 **Env-var injection** runs commands with the secret without it appearing on the command line or in bash history

---

## Features

| Tool | What It Does |
|------|-------------|
| `ask_secret` | Prompts the user via TUI dialog, stores in `AuthStorage` |
| `get_secret` | Retrieves metadata (key, length) — value cached in memory, **never in `content`** |
| `with_secret` | Runs a shell command with the secret injected as `$SECRET` env var — **never in `content`, session, or bash history** |
| `list_secrets` | Lists stored keys + persistence status |
| `clear_secret` | Deletes one secret (requires typed confirmation) |
| `forget_secrets` | Wipes ALL secrets (requires typed mantra) |
| `get_secret_store_path` | Shows `~/.pi/agent/auth.json` |
| `import_secret` | **NEW** — Import credentials from `.env`, JSON, or INI files into the secret store. Namespaces values by parent directory name. Optionally deletes the source file after import. |

#### `import_secret` — bulk credential import

Reads a credential file, detects its format (`.env`, `.json`, or INI-like), and stores each value in `AuthStorage` under a `namespace:key` derived from the file path.

**Namespace convention:**

| Source file | Namespace | Stored keys |
|-------------|-----------|-------------|
| `~/.aws/credentials` | `aws` | `aws:default:aws_access_key_id`, `aws:default:aws_secret_access_key` |
| `my-project/.env` | `my-project` | `my-project:DATABASE_URL`, `my-project:API_KEY` |
| `config/secrets.json` | `config` | `config:client_id`, `config:client_secret` |

**Flow:**
1. User or LLM calls `import_secret(path: "~/.aws/credentials")`
2. Tool reads, parses, shows what was found, asks for confirmation
3. Stores each value under `aws:default:aws_access_key_id` etc.
4. Offers to delete the source file (it's a liability once imported)
5. Values are then accessible via `get_secret` / `with_secret`

### Why this exists

| Problem | Without extension | With extension |
|---------|-----------------|----------------|
| LLM needs a credential you haven't given it | LLM asks in text, you copy-paste into chat | LLM calls `ask_secret`, TUI dialog appears |
| LLM retrieves a stored key | Value goes in tool `content` → session history → compaction | `get_secret` returns only metadata, `with_secret` injects as env var |
| LLM runs a command with a secret | The command appears in tool args, may leak via `ps` | `with_secret` spawns subprocess with secret in env, never on command line |
| You want to know what's stored | Edit JSON files manually | `list_secrets` |
| Secret rotation | Edit JSON files manually | `clear_secret` → `ask_secret` |

---

## Quick Start

```bash
pi install /path/to/secret-store
```

Then `/reload` and the tools are available to the LLM.

### LLM Workflow

```
User: "Set up the database with my credentials"

LLM:  ask_secret(key="db_password", prompt="Enter DB password:")
  →  TUI dialog → user pastes password → "Secret 'db_password' stored"

LLM:  get_secret(key="db_password")
  →  "Secret 'db_password' (12 chars) retrieved. Use with_secret to use it."

LLM:  with_secret(key="db_password", command="mysql -u root -p$SECRET < schema.sql")
  →  Secret injected as env var, never in content. Output returned.
```

### Bulk Import Workflow

```
User: "Set up the project from my .env file"

LLM:  import_secret(path="project/.env")
  →  Shows: "Found 3 credentials. Import?"
  →  User confirms → Stored as project:DATABASE_URL, etc.
  →  "Delete source file? [Y/n]"
  →  Source deleted, values available via get_secret/with_secret
```

---

## How It Works

```
LLM → tool call
        │
  ┌─────┴─────┐
  │ ask_secret │  ctx.ui.input() → TUI dialog → user enters value
  └─────┬─────┘
        │
        ▼
  ┌──────────────┐
  │  AuthStorage  │  ~/.pi/agent/auth.json (0600)
  │              │    or setRuntimeApiKey() for blocked/ephemeral
  └──────┬───────┘
         │
         ▼
  get_secret → returns metadata only, value cached in memory
  with_secret → looks up cached value, injects as $SECRET env var
                spawns via child_process.exec — never on command line
```

### Integration with PI's AuthStorage

The extension uses `AuthStorage` from `@earendil-works/pi-coding-agent`:

| `AuthStorage` method | Used by |
|---------------------|---------|
| `set(key, credential)` | `ask_secret` (persisted secrets) |
| `setRuntimeApiKey(key, value)` | `ask_secret` (blocked/ephemeral secrets) |
| `getApiKey(key)` | `get_secret`, `with_secret` (resolves `!commands`) |
| `has(key)` | `get_secret`, `with_secret`, `clear_secret` |
| `list()` | `list_secrets`, `forget_secrets` |
| `remove(key)` | `clear_secret`, `forget_secrets` |
| `reload()` | `session_start` |

### Supported value formats in `auth.json`

```json
{
  "github_token": { "type": "api_key", "key": "ghp_abc123" },
  "db_password":  { "type": "api_key", "key": "!pass show db/prod" },
  "aws_key":      { "type": "api_key", "key": "AWS_SECRET_ACCESS_KEY" }
}
```

| Format | Example | Resolution |
|--------|---------|-----------|
| Literal | `"sk-abc..."` | Used directly |
| Env var | `"MY_API_KEY"` | Read from environment |
| Command | `"!pass show api/key"` | Executed, stdout captured |

The `!command` syntax lets you wire in `pass`, `1password-cli`, `security`, or any secret manager without the extension needing to know about it.

---

## Security Model

### Two-step retrieval (get_secret → with_secret)

```
  get_secret("db_password")
    → value cached in memory Map
    → content: "Secret 'db_password' (12 chars) retrieved. Use with_secret..."
    →  ✓ session file has no value
    →  ✓ compaction has no value

  with_secret(key="db_password", command="mysql -u root -p$SECRET")
    → looks up Map["db_password"]
    → child_process.exec with env: { SECRET: "actual-value" }
    → command references env var name, not the value
    →  ✓ no secret in tool content
    →  ✓ no secret in session file
    →  ✓ no secret in bash history (non-interactive shell)
    →  ✓ no secret in /proc/*/cmdline (env only, not args)
    →  ⬜ brief exposure in /proc/*/environ (process lifetime)
```

### Blocklist

Keys matching these patterns (case-insensitive substring match) are **never persisted** — stored only as runtime overrides via `setRuntimeApiKey`:

`sudo`, `password`, `passwd`, `pass`, `root`, `admin`, `token`, `ssh_key`, `api_secret`, and variants.

### Confirmation dialogs

- `clear_secret` → must type the secret name to confirm
- `forget_secrets` → must type a random affirmation phrase

---

## Development

```bash
npm run validate    # tsc --noEmit --skipLibCheck
```

### Project Structure

```
secret-store/
├── package.json
├── tsconfig.json
├── src/extensions/secret-store/
│   ├── secret-store.ts    # Extension entry: tools, lifecycle, commands
│   └── confirm.ts         # Confirmation dialog helper
└── README.md
```

---

## License

MIT
