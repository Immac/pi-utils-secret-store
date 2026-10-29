# Changelog

## 1.3.0

### Added

- **Multi-secret injection in `with_secret`** — new optional `keys: string[]` parameter injects several secrets into ONE subprocess, each under a derived env var name (key uppercased, every non-alphanumeric run replaced by `_`; e.g. `kaggle_username` → `$KAGGLE_USERNAME`, `comfyui:server:cloud-comfy` → `$COMFYUI_SERVER_CLOUD_COMFY`; duplicates/collisions get deterministic `_2`, `_3`… suffixes). Provide exactly one of `key` / `keys`.
  - **All-or-nothing:** every key is resolved *before* execution — a missing or unresolvable key aborts with the culprit named; the command never runs with a partial credential set.
  - **Redaction for every injected value**, longest-first so a secret that is a substring of another cannot leak in fragments.
  - `validate: true` dry-runs the full mapping (var name, type, source per key) with zero value leakage.
  - `envVarName` is rejected in `keys` mode (single-`key` calls keep the exact legacy `$SECRET` / `envVarName` behavior).
  - Tool result details gained `keys` / `envVars` alongside the backward-compatible `key` / `envVar` fields; the TUI call/result renderers show the whole mapping.
- `deriveEnvVarName` / `deriveEnvVarMap` helpers (exported) + tests (`test/multi-secret.test.ts`).

## 1.2.1

### Fixed

- **`get_secret_store_path`, `get_active_backend`, and `/secret-path` reported a retired store** — all three hardcoded `SimpleSecretStore (~/.pi/agent/secrets.json)`, but `secrets.json` was retired on 2026-09-17; the real backend is `SimpleAuthStorage` at `getAgentDir()/auth.json`. They now report the live `auth.path`.
- **Stale path references in tool descriptions** (`ask_secret`, `with_secret`, `clear_secret`, `forget_secrets`) hardcoded `~/.pi/agent/...`, which is wrong whenever `PI_CODING_AGENT_DIR` points elsewhere (the common case). Paths are now derived from `getAgentDir()` or refer to `auth.json` generically.

### Added

- `SimpleAuthStorage.path` getter — public access to the backing file path so tools can report it truthfully.

## 1.2.0

### Added

- Revocability-based volatility rules: hard-block password/sudo/root/passphrase key shapes (never persisted), API keys and machine-issued tokens persist by default, plus env knobs for forcing volatility / allow-listing persistence, with tests.

## 1.1.0

### Fixed

- **Extension no longer crashes on load with pi v0.84.0+** — `AuthStorage` was removed from pi's public API in v0.84.0 (see [pi changelog](https://github.com/earendil-works/pi)). Replaced with `SimpleAuthStorage`, a self-contained credential manager that reads/writes `~/.pi/agent/auth.json` directly.

### Added

- `SimpleAuthStorage` class (`src/extensions/secret-store/auth-storage.ts`) — drop-in replacement for the exported `AuthStorage`, providing the same sync API (`has`, `get`, `set`, `remove`, `list`) plus runtime in-memory overrides (`setRuntimeApiKey`, `removeRuntimeApiKey`) and async `getApiKey` resolution.
- Test suite for `SimpleAuthStorage` covering CRUD, persistence, reload, runtime overrides, structured credential resolution, `!command` execution, and edge cases.

### Changed

- Updated devDependencies from pi v0.74.0 to v0.84.0 to match the current runtime.

### Context

Pi v0.84.0 consolidated auth management behind `ModelRuntime` as a single async facade. `AuthStorage` and its storage backends are no longer exported — the intended paths are `ModelRuntime` for provider auth, pi-ai `CredentialStore` for custom auth needs, or `readStoredCredential()` for one-off reads. None of these map cleanly to the secret-store extension's use case (arbitrary secrets with a sync API), so `SimpleAuthStorage` fills the gap.

## 1.0.0

Initial release.
