# 🔐 Secret Store

**LLM-safe secret management for pi agents.** Lets the LLM securely prompt for, retrieve, list, and manage secrets — without leaking them into conversation history.

![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=flat-square&logo=typescript)
![MIT License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Pi Extension](https://img.shields.io/badge/pi--extension-orange?style=flat-square)

---

## ✨ Features

- 🗣️ **Ask** via TUI dialog — paste-friendly `ctx.ui.input()` prompt
- 🔒 **Two-step retrieval** — `get_secret` returns metadata only; `with_secret` injects value as env var
- 🚫 **Blocklist** — prevents accidental persistence of sensitive key patterns (`sudo`, `password`, `token`, etc.)
- 📦 **Bulk import** — ingest `.env`, JSON, or INI credential files via `import_secret`
- 🧩 **Custom templates** — regex-based templates for non-standard file formats via `import_secret_template_add`
- 🗑️ **Safe deletion** — `clear_secret` (one) / `forget_secrets` (all) require typed confirmation
- 🔐 **Env-var injection** — runs commands with secret in environment, never on command line

---

## 📦 Tools

| Tool | Description |
|---|---|
| `ask_secret` | Prompt the user for a secret via TUI dialog, store in `AuthStorage` |
| `get_secret` | Retrieve metadata (key, length) — value cached in memory, **never in `content`** |
| `with_secret` | Run a shell command with secret injected as `$SECRET` env var — **never in session history** |
| `list_secrets` | List stored keys + persistence status (disk vs session-only) |
| `clear_secret` | Delete one secret (requires typed name to confirm) |
| `forget_secrets` | Wipe ALL secrets (requires typed affirmation phrase) |
| `import_secret` | Bulk import credentials from `.env`, JSON, or INI files |
| `import_secret_template_add` | Register a custom regex template for non-standard formats |
| `import_secret_template_list` | List registered custom templates |
| `import_secret_template_remove` | Remove a registered template |
| `get_secret_store_path` | Show `~/.pi/agent/auth.json` location |
| `get_active_backend` | Show which storage backend is active |

### Commands

| Command | Description |
|---|---|
| `/secrets` | List stored secrets (without values) from the TUI |
| `/secret-path` | Show the secret store file path |
| `/secret-import <path>` | Import credentials from a file interactively |

---

## 🚀 Quick Start

```bash
pi install /path/to/secret-store
# or: cp -r secret-store ~/.pi/agent/extensions/secret-store && /reload
```

### LLM Workflow

```
User: "Set up the database with my credentials"

LLM → ask_secret(key="db_password", prompt="Enter DB password:")
  → TUI dialog → user pastes password → "Secret 'db_password' stored"

LLM → get_secret(key="db_password")
  → "Secret 'db_password' (12 chars) retrieved. Use with_secret to use it."

LLM → with_secret(key="db_password", command="mysql -u root -p$SECRET < schema.sql")
  → Secret injected as env var, never in content. Output returned.
```

### Bulk Import Workflow

```
User: "Set up the project from my .env file"

LLM → import_secret(path="project/.env")
  → Shows: "Found 3 credentials in project/.env (env format):
      • project:DATABASE_URL
      • project:API_KEY
      • project:SECRET"
  → User confirms → Stored in AuthStorage
  → "Delete source file? [Y/n]" → Source deleted
  → Values available via get_secret / with_secret
```

---

## 💡 Usage Examples

### Storing a credential

```
ask_secret(key="github_token", prompt="Enter your GitHub PAT")
```

### Using a stored credential

```
with_secret(key="github_token", command="curl -H 'Authorization: Bearer $SECRET' https://api.github.com/user")
```

### Importing from a file

```
import_secret(path="~/.aws/credentials")
import_secret(path="project/.env")
import_secret(path="config/secrets.json")
```

### Importing with a custom template

```
# Register a template for netrc-style files
import_secret_template_add(
  name: "netrc",
  description: "netrc machine/login/password",
  pattern: "^machine\\s+(?<key>\\S+)\\s*\\n\\s+login\\s+\\S+\\s*\\n\\s+password\\s+(?<value>\\S+)",
  flags: "gm"
)

# Use it
import_secret(path: "~/.netrc", template: "netrc")

# Or use an inline template for a one-off format
import_secret(path: "server.cfg", template: {
  pattern: "^(?<key>\\w+)\\s*[:=]\\s*(?<value>.+)$",
  flags: "gm"
})
```

### Using a template with an inline pattern

When a named template doesn't exist yet, supply the pattern inline:

```
import_secret(path="server.cfg", template={
  pattern: "^(?<key>\\w+)\\s*=\\s*(?<value>.+)$",
  flags: "gm",
  skipPattern: "^#|^;"
})
```

---

## 🛡️ Security Model

### Two-step retrieval

```
get_secret("db_password")
  → value cached in memory Map
  → content: "Secret 'db_password' (12 chars) retrieved"
  → ✓ session file has no value
  → ✓ compaction has no value

with_secret(key="db_password", command="mysql -u root -p$SECRET")
  → looks up cached value
  → child_process.exec with env: { SECRET: "actual-value" }
  → ✓ no secret in tool content, session file, or bash history
  → ✓ no secret in /proc/*/cmdline (env only, not args)
```

### Blocklist

Keys matching these patterns (case-insensitive) are **never persisted** — stored only as runtime overrides:

`sudo`, `password`, `passwd`, `pass`, `root`, `admin`, `token`, `ssh_key`, `api_secret`

### Confirmation dialogs

| Action | Confirmation required |
|---|---|
| `clear_secret` | Type the secret name |
| `forget_secrets` | Type a random affirmation phrase |
| `import_secret` | Confirm credential list before storing |

---

## 🛠️ Development

```bash
npm run validate   # tsc --noEmit --skipLibCheck
npm test           # Run parser unit tests
```

### Project Structure

```
secret-store/
├── package.json
├── tsconfig.json
├── src/extensions/secret-store/
│   ├── secret-store.ts        # Extension entry: all tools, lifecycle, commands
│   ├── import-parsers.ts      # Parser module (extracted for testability)
│   └── confirm.ts             # Confirmation dialog helper
├── test/
│   └── import-parsers.test.ts # 31 unit tests
└── README.md
```

---

## 🔌 Companion Extension: Credential Guard

Pair Secret Store with [Credential Guard](https://github.com/Immac/pi-utils-credential-guard) to block reading of credential files at the tool level:

```
read(path="~/.aws/credentials")
  └─ credential-guard blocks
       └─ "Use import_secret to import this file"
            └─ import_secret(path="~/.aws/credentials")
                 └─ parsed → stored → optionally deleted
                      └─ get_secret / with_secret
```

| Installed | Behavior |
|---|---|
| Secret Store only | All tools work, but `read` can still leak credentials |
| Credential Guard only | In-memory fallback tools, no persistence |
| **Both** | Full protection: read blocked + persistent secret store |

---

## 📖 Resources

- [Pi Extension Docs](https://github.com/earendil-works/pi-coding-agent/blob/main/docs/extensions.md)
- [AuthStorage API](https://github.com/earendil-works/pi-coding-agent)
- [Credential Guard](https://github.com/Immac/pi-utils-credential-guard) — blocks reading of credential files

---

## 📄 License

MIT
