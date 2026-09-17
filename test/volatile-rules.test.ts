/**
 * Tests for the volatility rules (v1.2):
 *   — Human-knowledge secrets (password/sudo/root/passphrase shapes) are
 *     ALWAYS runtime-only — proof they can never be unlocked via env knobs.
 *   — Machine-issued, revocable secrets (api keys / tokens / PATs) are
 *     persistable by default.
 *   — SECRET_STORE_VOLATILE forces extra keys runtime-only.
 *   — SECRET_STORE_PERSIST_ALLOW re-enables persistence for soft look-alike
 *     keys only.
 */
import { isDoNotPersist } from "../src/extensions/secret-store/secret-store.js";

let failures = 0;
function check(name: string, got: boolean, want: boolean) {
  if (got !== want) { console.error(`✗ ${name}: expected ${want}, got ${got}`); failures++; }
  else console.log(`✓ ${name}`);
}

/** Set/delete env vars around a function, restoring afterwards. */
function withEnv(env: Record<string, string>, fn: () => boolean): boolean {
  const before = { ...process.env };
  try { Object.assign(process.env, env); return fn(); }
  finally { process.env = before; }
}

// ── Hard-blocked: always volatile ──
const hard = [
  "sudo", "sudo_password", "root_password", "my_password",
  "database_password", "ssh_key_passphrase", "pgpass", "mysql_password", "db_access_pass",
];
for (const k of hard) check(`hard: ${k} → volatile`, isDoNotPersist(k), true);

// ── Revocable machine secrets: persist by default ──
const soft = [
  "forgejo_api_key", "github_token", "github_pat",
  "WEBSEARCH_BRAVE_KEY", "access_token", "refresh_token_x", "admin", "ssh_key",
];
for (const k of soft) check(`soft: ${k} → persistable`, isDoNotPersist(k), false);

// ── PERSIST_ALLOW cannot unlock hard patterns ──
check("allowlist cannot unlock sudo_password",
  withEnv({ SECRET_STORE_PERSIST_ALLOW: "sudo_password" }, () => isDoNotPersist("sudo_password")),
  true);
check("allowlist cannot unlock database_password",
  withEnv({ SECRET_STORE_PERSIST_ALLOW: "db_password" }, () => isDoNotPersist("database_password")),
  true);

// ── VOLATILE forces extra keys (full + substring) ──
check("VOLATILE forces session_cookie",
  withEnv({ SECRET_STORE_VOLATILE: "session_cookie,refresh_token" }, () => isDoNotPersist("session_cookie")),
  true);
check("VOLATILE substring match",
  withEnv({ SECRET_STORE_VOLATILE: "refresh_token" }, () => isDoNotPersist("my_refresh_token_2")),
  true);
check("VOLATILE doesn't leak to unrelated keys",
  withEnv({ SECRET_STORE_VOLATILE: "refresh_token" }, () => isDoNotPersist("session_cookie")),
  false);
check("VOLATILE can't weaken hard block (sudo stays volatile)",
  withEnv({ SECRET_STORE_VOLATILE: "irrelevant" }, () => isDoNotPersist("sudo")),
  true);

if (failures > 0) { console.error(`\n${failures} test(s) failed`); process.exit(1); }
console.log("\nAll volatility-rules tests passed ✓");
