/**
 * Tests for credential file parsers (import-parsers.ts).
 *
 * Covering:
 * - detectFormat: format detection from file paths
 * - parseEnv: .env file parsing
 * - parseJson: JSON credential file parsing
 * - parseIni: INI-like credential file parsing
 * - deriveNamespace: namespace derivation from paths
 */

import { strict as assert } from "node:assert";
import {
  detectFormat,
  parseEnv,
  parseJson,
  parseIni,
  deriveNamespace,
} from "../src/extensions/secret-store/import-parsers.js";

// =============================================================================
// detectFormat
// =============================================================================

async function testDetectFormat_env() {
  assert.equal(detectFormat("/project/.env"), "env");
  assert.equal(detectFormat("/project/.env.local"), "env");
  assert.equal(detectFormat("/project/.env.production"), "env");
  console.log("  ✓ testDetectFormat_env");
}

async function testDetectFormat_json() {
  assert.equal(detectFormat("/project/secrets.json"), "json");
  assert.equal(detectFormat("/project/credentials.json"), "json");
  assert.equal(detectFormat("/project/config.json"), "json");
  console.log("  ✓ testDetectFormat_json");
}

async function testDetectFormat_ini() {
  assert.equal(detectFormat("/home/user/.aws/credentials"), "ini");
  assert.equal(detectFormat("/project/config.ini"), "ini");
  assert.equal(detectFormat("/project/auth.cfg"), "ini");
  // Unknown extensions fall back to ini
  assert.equal(detectFormat("/project/my-creds.txt"), "ini");
  assert.equal(detectFormat("/project/secret.yml"), "ini");
  console.log("  ✓ testDetectFormat_ini");
}

// =============================================================================
// parseEnv
// =============================================================================

async function testParseEnv_basic() {
  const result = parseEnv(`
DATABASE_URL=postgres://localhost:5432/mydb
API_KEY=sk-abc123
SECRET=supersecret
`);
  assert.equal(result.length, 3);
  assert.equal(result[0].key, "DATABASE_URL");
  assert.equal(result[0].value, "postgres://localhost:5432/mydb");
  assert.equal(result[1].key, "API_KEY");
  assert.equal(result[1].value, "sk-abc123");
  assert.equal(result[2].key, "SECRET");
  assert.equal(result[2].value, "supersecret");
  console.log("  ✓ testParseEnv_basic");
}

async function testParseEnv_withComments() {
  const result = parseEnv(`
# This is a comment
DATABASE_URL=postgres://localhost:5432/mydb
# Another comment
API_KEY=sk-abc123
`);
  assert.equal(result.length, 2);
  assert.equal(result[0].key, "DATABASE_URL");
  assert.equal(result[1].key, "API_KEY");
  console.log("  ✓ testParseEnv_withComments");
}

async function testParseEnv_quotedValues() {
  const result = parseEnv(`
DB_PASS='my secret pass'
APP_NAME="My App"
`);
  assert.equal(result.length, 2);
  assert.equal(result[0].key, "DB_PASS");
  assert.equal(result[0].value, "my secret pass");
  assert.equal(result[1].key, "APP_NAME");
  assert.equal(result[1].value, "My App");
  console.log("  ✓ testParseEnv_quotedValues");
}

async function testParseEnv_blankLines() {
  const result = parseEnv("KEY1=val1\n\n\nKEY2=val2\n  \nKEY3=val3");
  assert.equal(result.length, 3);
  assert.equal(result[0].key, "KEY1");
  assert.equal(result[2].key, "KEY3");
  console.log("  ✓ testParseEnv_blankLines");
}

async function testParseEnv_empty() {
  assert.equal(parseEnv("").length, 0);
  assert.equal(parseEnv("# just a comment").length, 0);
  assert.equal(parseEnv("   \n  \n").length, 0);
  console.log("  ✓ testParseEnv_empty");
}

// =============================================================================
// parseJson
// =============================================================================

async function testParseJson_basic() {
  const result = parseJson(`{
    "client_id": "abc123",
    "client_secret": "xyz789",
    "refresh_token": "tok_123"
  }`);
  assert.equal(result.length, 3);
  assert.equal(result[0].key, "client_id");
  assert.equal(result[0].value, "abc123");
  assert.equal(result[1].key, "client_secret");
  assert.equal(result[1].value, "xyz789");
  console.log("  ✓ testParseJson_basic");
}

async function testParseJson_skipsNonStrings() {
  const result = parseJson(`{
    "api_key": "sk-abc",
    "port": 8080,
    "enabled": true,
    "nested": { "inner": "val" },
    "items": ["a", "b"],
    "nothing": null
  }`);
  // Only api_key should be included (string value)
  assert.equal(result.length, 1);
  assert.equal(result[0].key, "api_key");
  assert.equal(result[0].value, "sk-abc");
  console.log("  ✓ testParseJson_skipsNonStrings");
}

async function testParseJson_emptyObjects() {
  assert.equal(parseJson("{}").length, 0);
  assert.equal(parseJson("[]").length, 0);
  console.log("  ✓ testParseJson_emptyObjects");
}

async function testParseJson_invalidJson() {
  assert.equal(parseJson("not json").length, 0);
  assert.equal(parseJson("").length, 0);
  console.log("  ✓ testParseJson_invalidJson");
}

// =============================================================================
// parseIni
// =============================================================================

async function testParseIni_basic() {
  const result = parseIni(`
[default]
aws_access_key_id = AKIA123
aws_secret_access_key = abc456
region = us-east-1
`);
  assert.equal(result.length, 3);
  assert.equal(result[0].key, "default:aws_access_key_id");
  assert.equal(result[0].value, "AKIA123");
  assert.equal(result[1].key, "default:aws_secret_access_key");
  assert.equal(result[1].value, "abc456");
  assert.equal(result[2].key, "default:region");
  assert.equal(result[2].value, "us-east-1");
  console.log("  ✓ testParseIni_basic");
}

async function testParseIni_multipleSections() {
  const result = parseIni(`
[default]
aws_access_key_id = AKIA123
[profile-dev]
aws_access_key_id = AKIA456
aws_secret_access_key = def789
`);
  assert.equal(result.length, 3);
  assert.equal(result[0].key, "default:aws_access_key_id");
  assert.equal(result[0].value, "AKIA123");
  assert.equal(result[1].key, "profile-dev:aws_access_key_id");
  assert.equal(result[1].value, "AKIA456");
  assert.equal(result[2].key, "profile-dev:aws_secret_access_key");
  assert.equal(result[2].value, "def789");
  console.log("  ✓ testParseIni_multipleSections");
}

async function testParseIni_unsectionedKeys() {
  const result = parseIni(`
host = example.com
port = 8080
`);
  assert.equal(result.length, 2);
  assert.equal(result[0].key, "host");
  assert.equal(result[1].key, "port");
  console.log("  ✓ testParseIni_unsectionedKeys");
}

async function testParseIni_comments() {
  const result = parseIni(`
# This is a comment
; This is also a comment
[default]
key = value
`);
  assert.equal(result.length, 1);
  assert.equal(result[0].key, "default:key");
  console.log("  ✓ testParseIni_comments");
}

async function testParseIni_colonSeparator() {
  const result = parseIni(`
[default]
aws_access_key_id: AKIA123
`);
  assert.equal(result.length, 1);
  assert.equal(result[0].key, "default:aws_access_key_id");
  assert.equal(result[0].value, "AKIA123");
  console.log("  ✓ testParseIni_colonSeparator");
}

async function testParseIni_quotedValues() {
  const result = parseIni(`
secret = "quoted value"
other = 'single quoted'
`);
  assert.equal(result.length, 2);
  assert.equal(result[0].value, "quoted value");
  assert.equal(result[1].value, "single quoted");
  console.log("  ✓ testParseIni_quotedValues");
}

async function testParseIni_empty() {
  assert.equal(parseIni("").length, 0);
  assert.equal(parseIni("# only a comment").length, 0);
  assert.equal(parseIni("; another comment").length, 0);
  console.log("  ✓ testParseIni_empty");
}

// =============================================================================
// deriveNamespace
// =============================================================================

async function testDeriveNamespace_aws() {
  const result = deriveNamespace("/home/user/.aws/credentials");
  assert.equal(result, "aws");
  console.log("  ✓ testDeriveNamespace_aws");
}

async function testDeriveNamespace_project() {
  // Use a known directory structure
  const result = deriveNamespace("/home/user/my-project/.env");
  assert.equal(result, "my-project");
  console.log("  ✓ testDeriveNamespace_project");
}

async function testDeriveNamespace_nested() {
  const result = deriveNamespace("/home/user/projects/alpha/config/secrets.json");
  assert.equal(result, "config");
  console.log("  ✓ testDeriveNamespace_nested");
}

async function testDeriveNamespace_tilde() {
  // This test relies on HOME env var being set
  const result = deriveNamespace("~/.aws/credentials");
  // Should resolve ~ to HOME, then take basename of dirname, strip leading dot
  assert.equal(result, "aws");
  console.log("  ✓ testDeriveNamespace_tilde");
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  console.log("Import Parsers Tests\n");

  // detectFormat
  await testDetectFormat_env();
  await testDetectFormat_json();
  await testDetectFormat_ini();

  // parseEnv
  await testParseEnv_basic();
  await testParseEnv_withComments();
  await testParseEnv_quotedValues();
  await testParseEnv_blankLines();
  await testParseEnv_empty();

  // parseJson
  await testParseJson_basic();
  await testParseJson_skipsNonStrings();
  await testParseJson_emptyObjects();
  await testParseJson_invalidJson();

  // parseIni
  await testParseIni_basic();
  await testParseIni_multipleSections();
  await testParseIni_unsectionedKeys();
  await testParseIni_comments();
  await testParseIni_colonSeparator();
  await testParseIni_quotedValues();
  await testParseIni_empty();

  // deriveNamespace
  await testDeriveNamespace_aws();
  await testDeriveNamespace_project();
  await testDeriveNamespace_nested();
  await testDeriveNamespace_tilde();

  console.log("\nAll import-parsers tests passed ✓");
}

main().catch((err) => {
  console.error("FAILED:", err);
  process.exit(1);
});
