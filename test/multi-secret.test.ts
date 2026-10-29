/**
 * Tests for multi-secret support (v1.3):
 *   — deriveEnvVarName: conventional env names derived from secret keys
 *   — deriveEnvVarMap: deterministic collision suffixes, order preserved
 *   — multi-secret redaction chain (longest-first) covers substring secrets
 */
import { deriveEnvVarName, deriveEnvVarMap } from "../src/extensions/secret-store/secret-store.js";
import { redactSecretFromOutput } from "../src/extensions/secret-store/import-parsers.js";

let failures = 0;
function check(name: string, got: unknown, want: unknown) {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) { console.error(`✗ ${name}: expected ${w}, got ${g}`); failures++; }
  else console.log(`✓ ${name}`);
}

// ── deriveEnvVarName ──
check("snake key", deriveEnvVarName("kaggle_username"), "KAGGLE_USERNAME");
check("colon-namespaced key", deriveEnvVarName("comfyui:server:cloud-comfy"), "COMFYUI_SERVER_CLOUD_COMFY");
check("prefixed key keeps prefix", deriveEnvVarName("tmp:GMAIL_REFRESH_TOKEN"), "TMP_GMAIL_REFRESH_TOKEN");
check("dash key", deriveEnvVarName("github-copilot"), "GITHUB_COPILOT");
check("already upper stays stable", deriveEnvVarName("KAGGLE_API_KEY"), "KAGGLE_API_KEY");
check("digit-leading gets underscore", deriveEnvVarName("2fa_token"), "_2FA_TOKEN");
check("symbol-only falls back", deriveEnvVarName("$$$"), "SECRET");
check("edge underscores collapse+trim", deriveEnvVarName("__a__b__"), "A_B");

// ── deriveEnvVarMap ──
check(
  "map preserves order",
  deriveEnvVarMap(["kaggle_username", "kaggle_api_key"]),
  [
    { key: "kaggle_username", envVar: "KAGGLE_USERNAME" },
    { key: "kaggle_api_key", envVar: "KAGGLE_API_KEY" },
  ]
);
check(
  "collisions get deterministic suffixes",
  deriveEnvVarMap(["foo:bar", "foo_bar", "foo-bar"]),
  [
    { key: "foo:bar", envVar: "FOO_BAR" },
    { key: "foo_bar", envVar: "FOO_BAR_2" },
    { key: "foo-bar", envVar: "FOO_BAR_3" },
  ]
);

// ── multi-secret redaction (mirrors execute's redactAll: longest-first) ──
const values = ["secret", "secret-extended"].sort((a, b) => b.length - a.length);
const redactAll = (s: string) => values.reduce((acc, v) => redactSecretFromOutput(acc, v), s);
check("both secrets redacted", redactAll("short=secret and long=secret-extended"), "short=[REDACTED] and long=[REDACTED]");
check("no substring residue", redactAll("xsecret-extendedx").includes("secret"), false);
check("short still redacted alone", redactAll("tok=secret;"), "tok=[REDACTED];");

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nAll multi-secret tests passed.");
