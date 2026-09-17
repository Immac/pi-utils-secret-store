/**
 * Tests for SimpleAuthStorage (auth-storage.ts).
 *
 * Covers:
 * - Basic CRUD: has, get, set, remove, list
 * - Persistence: writes survive reload
 * - Runtime overrides: setRuntimeApiKey, removeRuntimeApiKey
 * - getApiKey: resolves structured credentials and runtime overrides
 * - Edge cases: empty file, missing file, corrupt JSON, reload
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// We test SimpleAuthStorage by providing a temp authPath, bypassing getAgentDir.
// Import the class directly — it only uses getAgentDir as a default fallback.
// We'll construct instances with explicit paths so the import of getAgentDir
// at module level won't cause issues in test environments where pi-coding-agent
// may not be resolvable.

// Helper: create a SimpleAuthStorage with a temp auth.json
async function createStorage(testDir: string, initialData?: Record<string, unknown>) {
  const authPath = join(testDir, "auth.json");
  if (initialData) {
    writeFileSync(authPath, JSON.stringify(initialData, null, 2), "utf-8");
  }
  // Dynamic import to avoid module-level getAgentDir resolution issues
  const mod = await import("../src/extensions/secret-store/auth-storage.js");
  return new mod.SimpleAuthStorage(authPath);
}

// =============================================================================
// Basic CRUD
// =============================================================================

async function testHas_returnsTrueForExistingKey() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, { github_token: { type: "api_key", key: "abc" } });
    assert.equal(auth.has("github_token"), true);
    assert.equal(auth.has("nonexistent"), false);
    console.log("  ✓ testHas_returnsTrueForExistingKey");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testGet_returnsRawCredentialObject() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const cred = { type: "api_key", key: "sk-123" };
    const auth = await createStorage(dir, { my_key: cred });
    assert.deepEqual(auth.get("my_key"), cred);
    assert.equal(auth.get("missing"), undefined);
    console.log("  ✓ testGet_returnsRawCredentialObject");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testSet_persistsToDisk() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    auth.set("new_key", { type: "api_key", key: "value123" });
    // Read the file directly to confirm persistence
    const raw = readFileSync(join(dir, "auth.json"), "utf-8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.new_key.type, "api_key");
    assert.equal(parsed.new_key.key, "value123");
    console.log("  ✓ testSet_persistsToDisk");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testRemove_deletesFromDisk() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, { doomed: { type: "api_key", key: "x" } });
    assert.equal(auth.has("doomed"), true);
    auth.remove("doomed");
    assert.equal(auth.has("doomed"), false);
    // Confirm persisted
    const raw = readFileSync(join(dir, "auth.json"), "utf-8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.doomed, undefined);
    console.log("  ✓ testRemove_deletesFromDisk");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testList_returnsAllKeys() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, {
      alpha: { type: "api_key", key: "a" },
      beta: { type: "api_key", key: "b" },
    });
    const keys = auth.list().sort();
    assert.deepEqual(keys, ["alpha", "beta"]);
    console.log("  ✓ testList_returnsAllKeys");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testList_emptyWhenNoKeys() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    assert.deepEqual(auth.list(), []);
    console.log("  ✓ testList_emptyWhenNoKeys");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// =============================================================================
// Persistence across reload
// =============================================================================

async function testReload_picksUpExternalChanges() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const authPath = join(dir, "auth.json");
    writeFileSync(authPath, JSON.stringify({ old_key: { type: "api_key", key: "old" } }), "utf-8");
    const auth = await createStorage(dir);
    assert.equal(auth.has("old_key"), true);

    // Another process writes to the file
    writeFileSync(authPath, JSON.stringify({ new_key: { type: "api_key", key: "new" } }), "utf-8");
    auth.reload();
    assert.equal(auth.has("old_key"), false);
    assert.equal(auth.has("new_key"), true);
    console.log("  ✓ testReload_picksUpExternalChanges");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testConstructor_createsFileIfMissing() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const authPath = join(dir, "auth.json");
    // Constructor should create the file and initialize with empty data
    const auth = await createStorage(dir);
    const raw = readFileSync(authPath, "utf-8");
    assert.equal(raw, "{}");
    assert.deepEqual(auth.list(), []);
    console.log("  ✓ testConstructor_createsFileIfMissing");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testConstructor_handlesCorruptJson() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const authPath = join(dir, "auth.json");
    writeFileSync(authPath, "not valid json {{{", "utf-8");
    // Should not throw — preserves empty data
    const auth = await createStorage(dir);
    assert.deepEqual(auth.list(), []);
    // Setting a key should still work (overwrites corrupt file)
    auth.set("recovered", { type: "api_key", key: "ok" });
    assert.equal(auth.has("recovered"), true);
    console.log("  ✓ testConstructor_handlesCorruptJson");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// =============================================================================
// Runtime overrides (in-memory only)
// =============================================================================

async function testSetRuntimeApiKey_storesInMemory() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    auth.setRuntimeApiKey("sudo", "mypass");
    const value = await auth.getApiKey("sudo");
    assert.equal(value, "mypass");
    // Should NOT be in the file
    const raw = readFileSync(join(dir, "auth.json"), "utf-8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.sudo, undefined);
    console.log("  ✓ testSetRuntimeApiKey_storesInMemory");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testRemoveRuntimeApiKey_clearsOverride() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    auth.setRuntimeApiKey("temp_key", "temp_val");
    assert.equal(await auth.getApiKey("temp_key"), "temp_val");
    auth.removeRuntimeApiKey("temp_key");
    assert.equal(await auth.getApiKey("temp_key"), undefined);
    console.log("  ✓ testRemoveRuntimeApiKey_clearsOverride");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testRuntimeOverride_takesPrecedenceOverStored() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, {
      my_key: { type: "api_key", key: "stored_value" },
    });
    // Runtime override should win
    auth.setRuntimeApiKey("my_key", "runtime_value");
    assert.equal(await auth.getApiKey("my_key"), "runtime_value");
    // Remove override — should fall back to stored
    auth.removeRuntimeApiKey("my_key");
    assert.equal(await auth.getApiKey("my_key"), "stored_value");
    console.log("  ✓ testRuntimeOverride_takesPrecedenceOverStored");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// =============================================================================
// getApiKey resolution
// =============================================================================

async function testGetApiKey_resolvesStructuredCredential() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, {
      api_key: { type: "api_key", key: "sk-abc123" },
    });
    assert.equal(await auth.getApiKey("api_key"), "sk-abc123");
    console.log("  ✓ testGetApiKey_resolvesStructuredCredential");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testGetApiKey_returnsUndefinedForMissing() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    assert.equal(await auth.getApiKey("nonexistent"), undefined);
    console.log("  ✓ testGetApiKey_returnsUndefinedForMissing");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testGetApiKey_returnsUndefinedForNonApiKeyType() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, {
      oauth_cred: { type: "oauth", access: "tok", refresh: "ref", expires: 999 },
    });
    // Only "api_key" type gets resolved to a string
    assert.equal(await auth.getApiKey("oauth_cred"), undefined);
    console.log("  ✓ testGetApiKey_returnsUndefinedForNonApiKeyType");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testGetApiKey_resolvesBangCommand() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, {
      shell_secret: { type: "api_key", key: "!echo 'resolved_value'" },
    });
    assert.equal(await auth.getApiKey("shell_secret"), "resolved_value");
    console.log("  ✓ testGetApiKey_resolvesBangCommand");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testGetApiKey_returnsRawOnBangCommandFailure() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, {
      bad_cmd: { type: "api_key", key: "!false" },
    });
    // Command fails — should return the raw "!false" value
    assert.equal(await auth.getApiKey("bad_cmd"), "!false");
    console.log("  ✓ testGetApiKey_returnsRawOnBangCommandFailure");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// =============================================================================
// Edge cases
// =============================================================================

async function testSet_and_remove_multipleKeys() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    auth.set("k1", { type: "api_key", key: "v1" });
    auth.set("k2", { type: "api_key", key: "v2" });
    auth.set("k3", { type: "api_key", key: "v3" });
    assert.deepEqual(auth.list().sort(), ["k1", "k2", "k3"]);

    auth.remove("k2");
    assert.deepEqual(auth.list().sort(), ["k1", "k3"]);
    assert.equal(auth.has("k2"), false);
    console.log("  ✓ testSet_and_remove_multipleKeys");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testSet_overwritesExistingKey() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir, {
      key: { type: "api_key", key: "old_value" },
    });
    auth.set("key", { type: "api_key", key: "new_value" });
    assert.equal(await auth.getApiKey("key"), "new_value");
    console.log("  ✓ testSet_overwritesExistingKey");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testRemove_nonexistentKey_isNoOp() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    // Should not throw
    auth.remove("ghost");
    assert.deepEqual(auth.list(), []);
    console.log("  ✓ testRemove_nonexistentKey_isNoOp");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

async function testSetRawStringValue_isNotResolvedByGetApiKey() {
  const dir = mkdtempSync(join(tmpdir(), "ss-test-"));
  try {
    const auth = await createStorage(dir);
    // Setting a raw string (not a Credential object) — getApiKey only resolves
    // structured {type: "api_key", key: ...} objects, not bare strings
    auth.set("bare_string", "just a string");
    assert.equal(await auth.getApiKey("bare_string"), undefined);
    // But get() still returns it
    assert.equal(auth.get("bare_string"), "just a string");
    console.log("  ✓ testSetRawStringValue_isNotResolvedByGetApiKey");
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  console.log("Auth Storage Tests\n");

  // Basic CRUD
  await testHas_returnsTrueForExistingKey();
  await testGet_returnsRawCredentialObject();
  await testSet_persistsToDisk();
  await testRemove_deletesFromDisk();
  await testList_returnsAllKeys();
  await testList_emptyWhenNoKeys();

  // Persistence
  await testReload_picksUpExternalChanges();
  await testConstructor_createsFileIfMissing();
  await testConstructor_handlesCorruptJson();

  // Runtime overrides
  await testSetRuntimeApiKey_storesInMemory();
  await testRemoveRuntimeApiKey_clearsOverride();
  await testRuntimeOverride_takesPrecedenceOverStored();

  // getApiKey resolution
  await testGetApiKey_resolvesStructuredCredential();
  await testGetApiKey_returnsUndefinedForMissing();
  await testGetApiKey_returnsUndefinedForNonApiKeyType();
  await testGetApiKey_resolvesBangCommand();
  await testGetApiKey_returnsRawOnBangCommandFailure();

  // Edge cases
  await testSet_and_remove_multipleKeys();
  await testSet_overwritesExistingKey();
  await testRemove_nonexistentKey_isNoOp();
  await testSetRawStringValue_isNotResolvedByGetApiKey();

  console.log("\nAll auth-storage tests passed ✓");
}

main().catch((err) => {
  console.error("FAILED:", err);
  process.exit(1);
});
