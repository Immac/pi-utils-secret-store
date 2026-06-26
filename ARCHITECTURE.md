# Secret Store — Architecture

## Purpose & Goals

The Secret Store extension provides pi agents with safe, auditable credential management. Its core design goals:

1. **Zero leakage** — secrets never appear in tool results, conversation history, session files, or `/proc/*/cmdline`
2. **Safe defaults** — sensitive key patterns (`sudo`, `password`, `token`) are **never** written to disk, enforced at the tool level
3. **User consent** — all destructive operations (`clear`, `forget`, `import`) require explicit typed confirmation
4. **Bulk ingestion** — credential files (`.env`, JSON, INI) can be imported whole, then optionally deleted
5. **Extensible parsing** — custom regex templates for non-standard file formats

---

## System Components

```
┌─────────────────────────────────────────────────────────┐
│                   LLM Agent (tool calls)                 │
└──────────────┬──────────────┬──────────────┬───────────-─┘
               │              │              │
      ┌────────▼───┐   ┌─────▼──────┐  ┌───▼────────────┐
      │ Interactive │   │  Read-Only  │  │  Import Tools  │
      │   Tools     │   │   Tools     │  │                │
      │             │   │             │  │ secret-store.ts│
      │ ask_secret  │   │ get_secret  │  │  → detectFormat│
      │ clear_secret│   │ list_secrets│  │  → parseEnv    │
      │forget_secrets│  │ with_secret │  │  → parseJson   │
      │ import_secret│  │ (validate)  │  │  → parseIni    │
      └──────┬──────┘   └──────┬──────┘  │  → parseWithTmpl│
             │                 │         └───┬────────────┘
             ▼                 ▼             ▼
      ┌─────────────────────────────────────────────┐
      │          AuthStorage (~/.pi/agent/auth.json) │
      │  ┌─────────────┐  ┌──────────────────┐      │
      │  │ persisted    │  │ runtimeOverrides  │     │
      │  │ (this.data)  │  │ (in-memory map)  │     │
      │  └─────────────┘  └──────────────────┘      │
      └─────────────────────────────────────────────┘
             │                 │
             ▼                 ▼
      ┌─────────────┐  ┌──────────────┐
      │ auth.json   │  │ session-only │
      │ 0600 perms  │  │ (ephemeral)  │
      └─────────────┘  └──────────────┘
```

---

## Key Principles

### 1. Two-Tier Storage Model

The extension maintains two parallel storage tiers, tracked independently:

| Tier | Backend | Lifecycle | Use Case |
|------|---------|----------|----------|
| **Persisted** | `AuthStorage.data` → `auth.json` (0600) | Survives restarts | API keys, tokens, non-sensitive credentials |
| **Runtime** | `AuthStorage.runtimeOverrides` (in-memory) + `ephemeralSecrets` Set | Cleared on `session_shutdown` | Blocked keys (sudo, password, token, …), explicit `persist: false` |

**Why two tiers?** The `AuthStorage` API separates `set()` (persisted to JSON) from `setRuntimeApiKey()` (in-memory only). But `AuthStorage.has()` and `AuthStorage.list()` only query the persisted tier — they don't see runtime overrides. The extension bridges this gap with:

- `ephemeralSecrets: Set<string>` — tracks keys stored via `setRuntimeApiKey()`
- `volatileSecrets: Set<string>` — subset that can be deleted without confirmation
- `allSecretKeys(): string[]` — merges both tiers
- `secretExists(key): boolean` — checks both tiers
- `secretGet(key): unknown` — tries persisted first, then runtime

### 2. Two-Step Retrieval

```
get_secret(key)         → resolves value internally to verify accessibility
                          returns: "Secret 'key' retrieved. Use with_secret."
                          ✓ never reveals value, length, prefix, or suffix

with_secret(key, cmd)   → looks up value via AuthStorage.getApiKey()
                          → injects as $SECRET env var
                          → child_process.exec() with { env: { SECRET: value } }
                          ✓ never in tool result content
                          ✓ never in session history
                          ✓ never in /proc/*/cmdline
```

### 3. Absolute Blocklist (Enforced at Tool Level)

The blocklist is checked in `ask_secret()` *before* any storage call:

```typescript
function isDoNotPersist(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9_]/g, "");
  if (BLOCKLIST.has(normalized)) return true;
  for (const entry of BLOCKLIST) {
    if (normalized.includes(entry)) return true;  // substring match
  }
  return false;
}
```

Blocked keys are always stored via `setRuntimeApiKey()` regardless of the `persist` or `volatile` parameter. The `persist: true` override is explicitly ignored for blocked keys — this is intentional and non-negotiable.

### 4. Sequential Execution for Tool Safety

All user-interactive tools (`ask_secret`, `clear_secret`, `forget_secrets`, `import_secret`) set
`executionMode: "sequential"` to prevent parallel execution races on the shared TUI
`editorContainer`. `with_secret` is also sequential to prevent output interleaving.
The agent loop detects any sequential tool in a batch and executes all tools one at a time.

### 5. Confirmation-Only Destructive Operations

Three tools require user interaction:

| Tool | Confirmation Mechanism | Implementation |
|------|----------------------|----------------|
| `ask_secret` | TUI input dialog (masked) | `ctx.ui.input(prompt, "")` |
| `clear_secret(key)` | User types the exact key name | `confirmDestructiveAction(ctx, prompt, key)` |
| `forget_secrets()` | User types a random affirmation phrase | `confirmDestructiveAction(ctx, prompt, phrase)` |
| `import_secret(path)` | User confirms credential list, then optional delete | `ctx.ui.confirm(title, message)` |

### 6. Output Redaction

After running a command, `with_secret` automatically scans `stdout` and `stderr` (both in tool
content and the `details` result object) for the exact secret string and replaces it with
`[REDACTED]`. This catches accidental leakage from verbose tools (e.g., `curl` logging the
auth header) on both success and error output paths.

```typescript
export function redactSecretFromOutput(output: string, secret: string): string {
  const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return output.replace(new RegExp(escaped, "g"), "[REDACTED]");
}
```

### 7. Literal Secret Resolution (resolveConfigValue Bypass)

Secrets stored via `ask_secret` are resolved as **literal values** — the extension does
NOT pass them through AuthStorage's `resolveConfigValue`, which would interpret `$VARIABLE`
as environment variable references and `!command` as shell execution.

The `resolveSecretLiteral()` helper uses a three-tier resolution:

1. **Runtime override** → returned as-is (plain string, no interpolation)
2. **Persisted `api_key` credential** → extracts `.key` as a literal value
3. **OAuth / `!command` / env var** → falls back to `auth.getApiKey()` (preserves `resolveConfigValue`)

This means you can safely store passwords and tokens containing `$`, `!`, or `${}`
characters — they will be injected exactly as-entered into the command environment.

```typescript
async function resolveSecretLiteral(key: string): Promise<string | undefined> {
  // Runtime override — returned as-is
  if (ephemeralSecrets.has(key)) return auth.getApiKey(key);

  // Persisted api_key — literal extraction
  const cred = auth.get(key);
  if (cred?.type === "api_key" && typeof cred.key === "string" && cred.key.length > 0) {
    return cred.key;
  }

  // Fallback: OAuth, !command, env var
  return auth.getApiKey(key);
}
```

Secrets stored this way no longer execute `!echo pwned` as a shell command,
interpolate `${HOME}` into paths, or fail on `$` characters.

### 8. Format Detection for Import

The `import_secret` tool auto-detects file format from the path:

| Extension / Pattern | Format | Parser |
|---------------------|--------|--------|
| `.env` or `.env.*` | env | `parseEnv` — `KEY=VALUE`, `#` comments, quoted values |
| `.json` | json | `parseJson` — flat objects, string values only |
| Everything else | ini | `parseIni` — `[section]`, `key=value`, `#`/`;` comments |
| Custom template | template | `parseWithTemplate` — regex with named groups |

The namespace is derived from the parent directory name (e.g., `~/.aws/credentials` → `aws`, `/projects/myapp/.env` → `myapp`). Each credential is stored under `namespace:key` to avoid collisions.

---

## Interaction Flows

### Flow 1: User provides a credential

```
User: "My token is ghp_abc123"
  │
Agent: ask_secret(key="github_token", prompt="Enter your GitHub PAT")
  │
  ├─ ctx.ui.input("🔐 Enter your GitHub PAT", "")
  │     (masked dialog — all chars show as •)
  │
  ├─ User pastes "ghp_abc123"
  │
  ├─ isDoNotPersist("github_token")? → No (not blocked)
  │
  ├─ auth.set("github_token", { type: "api_key", key: "ghp_abc123" })
  │     → written to auth.json (0600 permissions)
  │
  └─ Result: "Stored secret 'github_token'. auth.json."
       ✓ No part of the value in result, session, or history
```

### Flow 2: Agent uses a stored credential

```
Agent: with_secret(key="github_token", command="curl -H 'Authorization: Bearer $SECRET' ...")
  │
  ├─ secretExists("github_token")? → Yes
  ├─ resolveSecretLiteral("github_token")
  │    ├─ ephemeral? → No
  │    ├─ api_key literal? → Yes, .key = "ghp_abc123"
  │    └─ returned directly (bypasses resolveConfigValue)
  │
  ├─ execAsync("curl ...", { env: { SECRET: "ghp_abc123" }, cwd, timeout, signal })
  │     ✓ Value only in child process environment, never in tool output
  │
  ├─ stdout + stderr both redacted via redactSecretFromOutput()
  │     ✓ Accidental leakage caught on both content and details paths
  │
  └─ Result: stdout from curl, with any accidental value occurrences redacted
```

### Flow 3: Bulk import credential file

```
User: "Import my AWS credentials"
  │
Agent: import_secret(path="~/.aws/credentials")
  │
  ├─ readFile → content
  ├─ detectFormat("~/.aws/credentials") → "ini"
  ├─ parseIni(content) → [{ key: "default:aws_access_key_id", value: "AKIA..." }, ...]
  ├─ deriveNamespace("~/.aws/credentials") → "aws"
  │
  ├─ ctx.ui.confirm("Import Credentials", "Found 2 credentials... Import?")
  │     User confirms ✓
  │
  ├─ auth.set("aws:default:aws_access_key_id", { type: "api_key", key: "AKIA..." })
  │     ... for each credential
  │
  ├─ ctx.ui.confirm("Delete Source File?", "... The original file is a liability.")
  │     User confirms ✓
  ├─ unlink("~/.aws/credentials")
  │
  └─ Result: "Imported 2 credential(s). Source deleted."
```

### Flow 4: Session lifecycle

```
session_start
  ├─ auth.reload() (re-read auth.json)
  ├─ count = allSecretKeys().length
  └─ ctx.ui.setStatus("secret-store", "🔐 7 secret(s)")

... (agent interacts via tools)

session_shutdown
  ├─ For each key in allSecretKeys():
  │     auth.removeRuntimeApiKey(key)
  ├─ ephemeralSecrets.clear()
  └─ volatileSecrets.clear()
       (runtime-only secrets lost; persisted secrets survive in auth.json)
```

---

## Lifecycle & State

### State Variables

| Variable | Type | Purpose |
|----------|------|---------|
| `auth` | `AuthStorage` | Singleton wrapping `~/.pi/agent/auth.json` |
| `ephemeralSecrets` | `Set<string>` | Keys stored via `setRuntimeApiKey()` (not in JSON) |
| `volatileSecrets` | `Set<string>` | Subset of ephemeral — no confirmation needed to delete |
| `templateCache` | `CredentialTemplate[] \| null` | Lazily loaded from `secret-import-templates.json` |

### Boot Order

1. Module loads → `AuthStorage.create()` initializes `auth`
2. Plugin factory `default function(pi: ExtensionAPI)` registers all tools
3. `session_start` → `auth.reload()` syncs with disk, sets status
4. Tools execute during conversation
5. `session_shutdown` → clears runtime state

---

## Testing

31 unit tests in `test/import-parsers.test.ts` covering:

| Suite | Tests | What |
|-------|-------|------|
| `detectFormat` | 3 | `.env`, `.json`, `.env.production`, auto-detection |
| `parseEnv` | 7 | `KEY=VALUE`, quotes, comments, blank lines, edge cases |
| `parseJson` | 5 | Flat objects, nested objects (skip), empty, invalid |
| `parseIni` | 7 | Sections, `key=val` / `key: val`, comments, quotes, section prefixes |
| `parseWithTemplate` | 5 | Custom regex, named groups, invalid patterns, skip patterns |
| `deriveNamespace` | 3 | Hidden dirs, `~` expansion, path resolution |
| `redactSecretFromOutput` | 1 | Exact match redaction, special chars, short secrets |

Run with: `npm test`
