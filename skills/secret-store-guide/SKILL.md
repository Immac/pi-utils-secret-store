---
name: secret-store-guide
description: >
  Tutorial and reference for the Secret Store pi extension. Teaches safe credential
  management — prompting users for secrets (passwords, API keys, tokens), storing
  them securely with optional persistence, and retrieving on demand. Covers all 7
  tools, the absolute do-not-persist blocklist, platform-native backends, common
  workflows, and security best practices. Load this skill when you need to manage
  credentials interactively for a user, or when the secret-store extension is
  installed and you want to understand its full capabilities.
---

# 🔐 Secret Store — Tutorial & Reference

## Overview

The Secret Store extension replaces insecure `read`/`bash` credential gathering with
**masked TUI dialogs** and safe storage (in-memory or persisted). The agent calls
`ask_secret` → user types in a `•`-masked dialog → secret is stored → agent
retrieves it later with `get_secret`.

**Credential Guard** is a companion extension that blocks reading of credential
files at the tool level. When both are installed, `import_secret` lets you safely
ingest `.env` or `.aws/credentials` into the store instead of reading them raw.

**Load this skill when** you need to ask for, retrieve, list, or clear credentials,
or when the user mentions "secrets", "credentials", "stored passwords", "tokens",
or "credential guard".

---

## 1. Install & Verify

```bash
pi install /path/to/secret-store    # or symlink: ln -s ... ~/.pi/agent/packages/secret-store
/reload                             # then reload pi
```

**Verify:** `/secrets` → "No secrets stored" · `/secret-path` → shows active backend

**Deps:** Node.js 18+. Platform backends auto-detected: Linux `libsecret-tools`, macOS Keychain, Win Credential Manager. Encrypted file fallback always available.

---

## 2. Tool Reference

All 12 tools. **Key security rule:** keys matching `sudo`, `password`, `passwd`,
`pass`, `root`, `admin`, `token`, `ssh_key`, `api_secret`, and patterns like
`root_password` / `db_password` / `access_token` are **NEVER persisted**
(case-insensitive substring match). The blocklist is absolute — `persist: true`
has no effect on blocked keys.

### `ask_secret(key, prompt, persist?)`

Prompt user via masked dialog — all chars display as `•`. Returns only the key
name and persistence status. **Never reveals any part of the value** (no prefix,
no suffix, no character count). The value is available for `with_secret`.

- Blocked keys → always in-memory (🧠). Non-blocked → persisted by default (💾).
- `persist: false` keeps a non-blocked key memory-only. `persist: true` = default.
- Result text: `Stored secret "github_token". auth.json.` or `session-only.`

### `get_secret(key)`

Confirms a secret is accessible. **Never reveals any part of the value** —
no prefix, no suffix, no character count. The secret is resolved internally to
verify it can be used, but only `with_secret` injects it into a command.
Returns "not found" if key doesn't exist, or "retrieved" with persistence status.

### `with_secret(key, command, envVarName?, timeout?, validate?)`

Runs a shell command with the secret injected as an environment variable.
The value is never exposed in tool content, session history, or bash history.
Reference via `$SECRET` (or `$envVarName` if set).

Use `validate: true` to dry-run — checks the secret is accessible and reports
its type (plain string, structured) and source (auth.json, session-only)
**without revealing any part of the value**.

### `list_secrets()`

Shows all keys with persistence icons: `💾 github_token (persisted)`,
`🧠 sudo (session-only)`. Values never exposed.

### `clear_secret(key)`

User must **type the key name** to confirm. Prevents accidental deletion.
After clearing, re-prompt with `ask_secret`.

### `forget_secrets()`

**Irreversible.** User must type a random confirmation phrase. Wipes all
secrets from disk and memory. No undo.

### `get_secret_store_path()` / `get_active_backend()`

Return active backend name. Possible values: `secret-service` (Linux),
`macos-keychain` (macOS), `windows-credential-manager` (Win),
`encrypted-file` (fallback, AES-256-GCM).

### `import_secret(path, template?)`

Bulk import credentials from a file into the secret store. Detects format from
file path (`.env`, `.json`, or INI-like). Values stored under `namespace:key`
where namespace is the parent directory name (e.g., `~/.aws/credentials` →
`aws:default:aws_access_key_id`).

Optional `template` parameter accepts:
- **String**: name of a registered template (see `import_secret_template_add`)
- **Object**: inline pattern `{ pattern, flags, keyGroup?, valueGroup?, skipPattern? }`

**Flow:** reads file → parses → confirms with user → stores → optionally deletes source.

### `import_secret_template_add(name, description, pattern, flags?, keyGroup?, valueGroup?, filePattern?, skipPattern?)`

Register a custom regex template for parsing non-standard credential file formats.
Pattern must include `(?<key>...)` and `(?<value>...)` named capture groups.

### `import_secret_template_list()`

List all registered custom templates with descriptions and auto-detect patterns.

### `import_secret_template_remove(name)`

Remove a previously registered template by name.

### Commands

| Command | Action |
|---------|--------|
| `/secrets` | List stored keys (interactive) |
| `/secret-path` | Show active backend name |
| `/secret-import <path>` | Import credentials from a file interactively |

---

## 3. Workflows

### First-time credential

```
User: "Deploy to production using my GitHub token"
Agent: ask_secret("github_token", "Enter your GitHub PAT:")
  → user types in masked dialog → stored
     get_secret("github_token") → uses it for deployment
```

### Reuse existing

```
User: "Push to GitHub"
Agent: list_secrets() → sees "github_token" → get_secret("github_token")
```

### Rotate a credential

```
User: "Update my GitHub token"
Agent: clear_secret("github_token") → user types name to confirm
  → ask_secret("github_token", "Enter your new token")
```

### Bulk import from a file

```
User: "Set up the project from .env"
Agent: import_secret(path="project/.env")
  → parses as .env format → lists found keys → user confirms
  → stored as project:DATABASE_URL, project:API_KEY etc.
  → "Delete source file?" → optionally removes the plaintext
  → Values available via get_secret / with_secret
```

### Import with a custom template

```
User: "Import credentials from my server config"
Agent: import_secret_template_add(
         name="server-config",
         pattern="^(?<key>\\w+)\\s*=\\s*(?<value>.+)$",
         flags="gm")
  → import_secret(path="server.cfg", template="server-config")
  → parses using the custom regex → user confirms → stored
```

### Using with_secret (safe command execution)

```
User: "Deploy using my db password"
Agent: with_secret(key="db_password",
         command="mysql -u root -p$SECRET < schema.sql")
  → secret injected as env var, never in session history
```

### Session-only (blocked) credentials

```
User: "SSH into the server as root"
Agent: ask_secret("root_password", "...") → stored ephemerally (🧠, blocked)
  → get_secret("root_password") → use → optionally clear after
```

### Cleanup

```
Agent: "Done. Should I clear the credentials?"
User: "Yes"
Agent: forget_secrets() or clear_secret(...) per key → user confirms
```

---

## 4. Best Practices

**For agents:**
- Always use `ask_secret` — never `read`/`bash` for credentials
- Check `list_secrets()` first before re-prompting the same key
- Use meaningful key names (`github_token` not `key1`)
- Use `with_secret` to run commands with secrets — `$SECRET` env var never leaks
- For bulk imports, use `import_secret(path)` — it handles `read`-blocked files
- Register custom regex templates for non-standard file formats
- Clear ephemeral secrets after use

**For users:**
- Backspace corrects, Ctrl+U clears, Escape cancels
- `/secrets` to see stored keys, `/secret-path` to check backend
- Blocked keys are never on disk by design — re-enter each session
- `clear_secret` + `ask_secret` is the rotation pattern

---

## 5. Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| No dialog | Not in interactive mode (`--print`/`--json`). Falls back to unmasked `ui.input()`. |
| Secret lost on restart | Blocked key (🧠) is ephemeral. Or backend changed — check `get_active_backend()`. |
| "Not found" but stored | Was it blocked? Was it cleared in a prior session? Run `list_secrets()`. |
| Encrypted file broken | Machine-id changed (containers)? `.pi/agent/` must be `0700`, `secrets.enc` `0600`. Both files (`secrets.enc` + `.salt`) required. |
| Accidental wipe | Confirmation required to wipe — user typed the phrase. No undo. Re-enter credentials. |

**Audit checklist:** `list_secrets()` shows only expected keys · Blocked keys show 🧠 · `secrets.enc` permissions `0600` · `~/.pi/agent/` permissions `0700` · No secrets visible in logs/errors.

---

## 6. Quick Reference

```
┌───────────────────────────────────────────────────────────┐
│                  SECRET STORE — QUICK REFERENCE            │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  ask_secret(key, prompt, persist?)                        │
│    → masked dialog → store → key + status only, never value│
│  get_secret(key)         → metadata only; use with_secret │
│  with_secret(key, cmd)   → $SECRET env var, never in text │
│  list_secrets()          → keys with 💾/🧠 icons           │
│  clear_secret(key)       → user types key to confirm      │
│  forget_secrets()        → user types random phrase       │
│  import_secret(path)     → bulk import .env/json/INI      │
│  import_secret_template_add / list / remove               │
│    → custom regex templates for non-standard formats      │
│  get_secret_store_path() → backend name                   │
│  get_active_backend()    → backend name only              │
│                                                           │
│  🧠 = ephemeral (session)    💾 = persisted (survives)    │
│  🔒 Blocked keys NEVER persisted (sudo, password, token…) │
│                                                           │
│  Commands: /secrets  /secret-path  /secret-import <path>  │
└───────────────────────────────────────────────────────────┘
└───────────────────────────────────────────────────────────┘
```
