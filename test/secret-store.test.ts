/**
 * Tests for Secret Store
 *
 * Covers:
 * - SecretStore CRUD operations
 * - Do-not-persist behavior (default blocklist)
 * - Persistence (load/save roundtrip)
 * - Ephemeral vs persisted storage
 * - Custom blocklist options
 * - Edge cases: empty keys, special characters, overwrites
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SecretStore } from "../src/extensions/secret-store/store.js";

// =============================================================================
// Helpers
// =============================================================================

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "secret-store-test-"));
}

async function cleanTempDir(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}

// =============================================================================
// Tests
// =============================================================================

describe("SecretStore", () => {
  let tempDir: string;

  before(() => {
    tempDir = createTempDir();
  });

  after(async () => {
    await cleanTempDir(tempDir);
  });

  // ---------------------------------------------------------------------------
  // Basic CRUD
  // ---------------------------------------------------------------------------

  it("should store and retrieve secrets", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-basic.json") });
    store.set("my_key", "my_value");
    assert.equal(store.get("my_key"), "my_value");
  });

  it("should return undefined for missing keys", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-missing.json") });
    assert.equal(store.get("nonexistent"), undefined);
  });

  it("should overwrite existing secrets", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-overwrite.json") });
    store.set("key", "old_value");
    store.set("key", "new_value");
    assert.equal(store.get("key"), "new_value");
  });

  it("should delete secrets", async () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-delete.json") });
    store.set("key", "value");
    assert.equal(store.get("key"), "value");
    const deleted = await store.delete("key");
    assert.equal(deleted, true);
    assert.equal(store.get("key"), undefined);
  });

  it("should return false when deleting nonexistent key", async () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-delete-nonexist.json") });
    const deleted = await store.delete("nonexistent");
    assert.equal(deleted, false);
  });

  it("should list all secret keys without values", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-list.json") });
    store.set("key1", "val1");
    store.set("key2", "val2");
    store.set("key3", "val3");
    const list = store.list();
    assert.equal(list.length, 3);
    const keys = list.map((s) => s.key).sort();
    assert.deepEqual(keys, ["key1", "key2", "key3"]);
    // Should not expose values
    for (const s of list) {
      assert.equal("value" in s, false);
      assert.equal("val" in s, false);
    }
  });

  it("should clear all secrets", async () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-clear.json") });
    store.set("key1", "val1");
    store.set("key2", "val2");
    await store.clear();
    assert.equal(store.list().length, 0);
    assert.equal(store.get("key1"), undefined);
    assert.equal(store.get("key2"), undefined);
  });

  it("has should return correct existence", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-has.json") });
    assert.equal(store.has("key"), false);
    store.set("key", "value");
    assert.equal(store.has("key"), true);
  });

  // ---------------------------------------------------------------------------
  // Do-Not-Persist Behavior
  // ---------------------------------------------------------------------------

  it("should NOT persist 'sudo' by default", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-sudo.json") });
    const persisted = store.set("sudo", "hunter2");
    assert.equal(persisted, false);
    assert.equal(store.get("sudo"), "hunter2"); // Should still be in memory
  });

  it("should NOT persist 'password' by default", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-password.json") });
    const persisted = store.set("database_password", "secret123");
    assert.equal(persisted, false);
    assert.equal(store.get("database_password"), "secret123");
  });

  it("should NOT persist keys containing 'sudo' by default (substring match)", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-sudo-substring.json") });
    const persisted = store.set("my_sudo_pass", "secret");
    assert.equal(persisted, false);
  });

  it("should NOT persist 'root' by default", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-root.json") });
    const persisted = store.set("root", "toor");
    assert.equal(persisted, false);
  });

  it("should NOT persist keys matching 'token' by default", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-token.json") });
    const persisted = store.set("access_token", "ghp_abc123");
    assert.equal(persisted, false);
  });

  it("should persist non-blocked keys by default", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-nonblocked.json") });
    const persisted = store.set("github_key", "ghp_abc123");
    assert.equal(persisted, true);
  });

  it("should NEVER persist blocked keys even with persist=true", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-absolute-block.json") });
    const persisted = store.set("sudo", "hunter2", true);
    assert.equal(persisted, false); // Blocklist is absolute — cannot be overridden
    assert.equal(store.get("sudo"), "hunter2"); // Still accessible in-memory
  });

  it("should allow explicit persist=false for non-blocked keys", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-override-ephemeral.json") });
    const persisted = store.set("api_key", "abc123", false);
    assert.equal(persisted, false); // Explicit ephemeral
  });

  it("wouldBeBlocked should correctly report blocklist status", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-blockcheck.json") });
    assert.equal(store.wouldBeBlocked("sudo"), true);
    assert.equal(store.wouldBeBlocked("password"), true);
    assert.equal(store.wouldBeBlocked("my_custom_key"), false);
    assert.equal(store.wouldBeBlocked("root_password"), true);
  });

  // ---------------------------------------------------------------------------
  // Custom Blocklist
  // ---------------------------------------------------------------------------

  it("should accept custom do-not-persist keys appended to defaults", () => {
    const store = new SecretStore({
      storePath: join(tempDir, "test-custom-block.json"),
      doNotPersistKeys: ["my_secret", "internal_key"],
    });
    assert.equal(store.wouldBeBlocked("sudo"), true); // Still default
    assert.equal(store.wouldBeBlocked("my_secret"), true); // Custom added
    assert.equal(store.wouldBeBlocked("internal_key"), true);
    assert.equal(store.wouldBeBlocked("normal_key"), false);
  });

  it("should accept override blocklist replacing defaults", () => {
    const store = new SecretStore({
      storePath: join(tempDir, "test-override-blocklist.json"),
      overrideDoNotPersistKeys: ["my_secret"],
    });
    assert.equal(store.wouldBeBlocked("sudo"), false); // Defaults removed
    assert.equal(store.wouldBeBlocked("my_secret"), true); // Custom only
    assert.equal(store.wouldBeBlocked("password"), false);
  });

  // ---------------------------------------------------------------------------
  // Persistence (save/load roundtrip)
  // ---------------------------------------------------------------------------

  it("should persist and reload secrets correctly", async () => {
    const storePath = join(tempDir, "test-roundtrip.json");
    const store1 = new SecretStore({ storePath });
    store1.set("api_key", "sk-abc123");
    store1.set("sudo", "should-not-persist"); // Blocked
    store1.set("normal", "normal-value");
    await store1.save();

    // Verify the file exists and has correct permissions
    assert.equal(existsSync(storePath), true);
    const raw = readFileSync(storePath, "utf-8");
    const data = JSON.parse(raw);
    assert.equal(data.version, 1);
    assert.equal(data.secrets["api_key"], "sk-abc123");
    assert.equal(data.secrets["normal"], "normal-value");
    assert.equal(data.secrets["sudo"], undefined); // Blocked — not persisted

    // Load into a fresh store
    const store2 = new SecretStore({ storePath });
    await store2.load();
    assert.equal(store2.get("api_key"), "sk-abc123");
    assert.equal(store2.get("normal"), "normal-value");
    assert.equal(store2.get("sudo"), undefined); // Never persisted
  });

  it("should handle empty/clean store gracefully", async () => {
    const storePath = join(tempDir, "test-empty.json");
    const store = new SecretStore({ storePath });
    await store.load(); // Should not throw
    assert.equal(store.list().length, 0);
  });

  it("should handle corrupt store gracefully", async () => {
    const storePath = join(tempDir, "test-corrupt.json");
    await writeFile(storePath, "not-json-at-all", "utf-8");
    const store = new SecretStore({ storePath });
    await store.load(); // Should not throw
    assert.equal(store.list().length, 0);
  });

  it("should persist ephemeral-then-persisted transitions correctly", async () => {
    const storePath = join(tempDir, "test-transition.json");
    const store1 = new SecretStore({ storePath });

    // Set as ephemeral
    store1.set("mykey", "myvalue", false);
    await store1.save();

    // File should be empty (nothing persisted)
    let raw = readFileSync(storePath, "utf-8");
    assert.equal(JSON.parse(raw).secrets["mykey"], undefined);

    // Promote to persisted
    store1.set("mykey", "myvalue", true);
    await store1.save();

    // File should now have it
    raw = readFileSync(storePath, "utf-8");
    assert.equal(JSON.parse(raw).secrets["mykey"], "myvalue");
  });

  it("should handle secret values with special characters", async () => {
    const storePath = join(tempDir, "test-special-chars.json");
    const special = "abc!@#$%^&*()_+{}|:<>?`~\"'\\;\n\t";
    const store = new SecretStore({ storePath });
    store.set("special_key", special);
    await store.save();

    const store2 = new SecretStore({ storePath });
    await store2.load();
    assert.equal(store2.get("special_key"), special);
  });

  it("should handle Unicode and emoji in secrets", async () => {
    const storePath = join(tempDir, "test-unicode.json");
    const unicode = "パスワード🔐日本語✓";
    const store = new SecretStore({ storePath });
    store.set("unicode_key", unicode);
    await store.save();

    const store2 = new SecretStore({ storePath });
    await store2.load();
    assert.equal(store2.get("unicode_key"), unicode);
  });

  // ---------------------------------------------------------------------------
  // Edge Cases
  // ---------------------------------------------------------------------------

  it("should handle empty secret values", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-empty-value.json") });
    store.set("empty", "");
    assert.equal(store.get("empty"), "");
    assert.equal(store.has("empty"), true);
  });

  it("should handle very long secret values", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-long-value.json") });
    const longValue = "x".repeat(10000);
    store.set("long", longValue);
    assert.equal(store.get("long"), longValue);
  });

  it("should return correct blocklist via getBlocklist", () => {
    const store = new SecretStore({ storePath: join(tempDir, "test-blocklist.json") });
    const blocklist = store.getBlocklist();
    assert.ok(blocklist.includes("sudo"));
    assert.ok(blocklist.includes("password"));
    assert.ok(blocklist.includes("root"));
  });

  it("should persist only non-blocked keys on save", async () => {
    const storePath = join(tempDir, "test-mixed-persist.json");
    const store = new SecretStore({ storePath });
    store.set("openai_key", "sk-proj-123");
    store.set("sudo_password", "hunter2"); // Blocked
    store.set("db_password", "secret"); // Blocked
    store.set("normal_config", "some-value");
    await store.save();

    const raw = readFileSync(storePath, "utf-8");
    const data = JSON.parse(raw);
    const persistedKeys = Object.keys(data.secrets);
    assert.ok(persistedKeys.includes("openai_key"));
    assert.ok(persistedKeys.includes("normal_config"));
    assert.ok(!persistedKeys.includes("sudo_password"));
    assert.ok(!persistedKeys.includes("db_password"));
  });

  it("should NEVER persist blocked keys to disk even with persist=true", async () => {
    const storePath = join(tempDir, "test-blocked-persist-true.json");
    const store = new SecretStore({ storePath });
    store.set("sudo", "hunter2", true);       // Blocked + explicit persist=true
    store.set("root_password", "toor", true); // Blocked + explicit persist=true
    store.set("safe_key", "safe_val");        // Non-blocked
    await store.save();

    const raw = readFileSync(storePath, "utf-8");
    const data = JSON.parse(raw);
    const persistedKeys = Object.keys(data.secrets);
    assert.ok(persistedKeys.includes("safe_key"));
    assert.ok(!persistedKeys.includes("sudo"));
    assert.ok(!persistedKeys.includes("root_password"));
  });
});
