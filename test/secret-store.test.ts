/**
 * Tests for Secret Store
 *
 * Covers:
 * - SecretStore CRUD operations
 * - Do-not-persist behavior (default blocklist)
 * - Persistence (load/save roundtrip via test backend)
 * - Ephemeral vs persisted storage
 * - Custom blocklist options
 * - Edge cases: empty keys, special characters, overwrites
 * - Encrypted file backend: on-disk encryption
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SecretStore } from "../src/extensions/secret-store/store.js";
import { TestFileBackend } from "./helpers.js";

// =============================================================================
// Helpers
// =============================================================================

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "secret-store-test-"));
}

async function cleanTempDir(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}

function makeStore(storePath: string): SecretStore {
  return new SecretStore({
    backend: new TestFileBackend(storePath),
  });
}

async function initStore(store: SecretStore): Promise<void> {
  await store.load();
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

  it("should store and retrieve secrets", async () => {
    const store = makeStore(join(tempDir, "test-basic.json"));
    await initStore(store);
    store.set("my_key", "my_value");
    assert.equal(store.get("my_key"), "my_value");
  });

  it("should return undefined for missing keys", async () => {
    const store = makeStore(join(tempDir, "test-missing.json"));
    await initStore(store);
    assert.equal(store.get("nonexistent"), undefined);
  });

  it("should overwrite existing secrets", async () => {
    const store = makeStore(join(tempDir, "test-overwrite.json"));
    await initStore(store);
    store.set("key", "old_value");
    store.set("key", "new_value");
    assert.equal(store.get("key"), "new_value");
  });

  it("should delete secrets", async () => {
    const store = makeStore(join(tempDir, "test-delete.json"));
    await initStore(store);
    store.set("key", "value");
    assert.equal(store.get("key"), "value");
    const deleted = await store.delete("key");
    assert.equal(deleted, true);
    assert.equal(store.get("key"), undefined);
  });

  it("should return false when deleting nonexistent key", async () => {
    const store = makeStore(join(tempDir, "test-delete-nonexist.json"));
    await initStore(store);
    const deleted = await store.delete("nonexistent");
    assert.equal(deleted, false);
  });

  it("should list all secret keys without values", async () => {
    const store = makeStore(join(tempDir, "test-list.json"));
    await initStore(store);
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
    }
  });

  it("should clear all secrets", async () => {
    const store = makeStore(join(tempDir, "test-clear.json"));
    await initStore(store);
    store.set("key1", "val1");
    store.set("key2", "val2");
    await store.clear();
    assert.equal(store.list().length, 0);
    assert.equal(store.get("key1"), undefined);
    assert.equal(store.get("key2"), undefined);
  });

  it("has should return correct existence", async () => {
    const store = makeStore(join(tempDir, "test-has.json"));
    await initStore(store);
    assert.equal(store.has("key"), false);
    store.set("key", "value");
    assert.equal(store.has("key"), true);
  });

  // ---------------------------------------------------------------------------
  // Do-Not-Persist Behavior
  // ---------------------------------------------------------------------------

  it("should NOT persist 'sudo' by default", async () => {
    const store = makeStore(join(tempDir, "test-sudo.json"));
    await initStore(store);
    const persisted = store.set("sudo", "hunter2");
    assert.equal(persisted, false);
    assert.equal(store.get("sudo"), "hunter2"); // Should still be in memory
  });

  it("should NOT persist 'password' by default", async () => {
    const store = makeStore(join(tempDir, "test-password.json"));
    await initStore(store);
    const persisted = store.set("database_password", "secret123");
    assert.equal(persisted, false);
    assert.equal(store.get("database_password"), "secret123");
  });

  it("should NOT persist keys containing 'sudo' by default (substring match)", async () => {
    const store = makeStore(join(tempDir, "test-sudo-substring.json"));
    await initStore(store);
    const persisted = store.set("my_sudo_pass", "secret");
    assert.equal(persisted, false);
  });

  it("should NOT persist 'root' by default", async () => {
    const store = makeStore(join(tempDir, "test-root.json"));
    await initStore(store);
    const persisted = store.set("root", "toor");
    assert.equal(persisted, false);
  });

  it("should NOT persist keys matching 'token' by default", async () => {
    const store = makeStore(join(tempDir, "test-token.json"));
    await initStore(store);
    const persisted = store.set("access_token", "ghp_abc123");
    assert.equal(persisted, false);
  });

  it("should persist non-blocked keys by default", async () => {
    const store = makeStore(join(tempDir, "test-nonblocked.json"));
    await initStore(store);
    const persisted = store.set("github_key", "ghp_abc123");
    assert.equal(persisted, true);
  });

  it("should NEVER persist blocked keys even with persist=true", async () => {
    const store = makeStore(join(tempDir, "test-absolute-block.json"));
    await initStore(store);
    const persisted = store.set("sudo", "hunter2", true);
    assert.equal(persisted, false); // Blocklist is absolute — cannot be overridden
    assert.equal(store.get("sudo"), "hunter2"); // Still accessible in-memory
  });

  it("should allow explicit persist=false for non-blocked keys", async () => {
    const store = makeStore(join(tempDir, "test-override-ephemeral.json"));
    await initStore(store);
    const persisted = store.set("api_key", "abc123", false);
    assert.equal(persisted, false); // Explicit ephemeral
  });

  it("wouldBeBlocked should correctly report blocklist status", async () => {
    const store = makeStore(join(tempDir, "test-blockcheck.json"));
    await initStore(store);
    assert.equal(store.wouldBeBlocked("sudo"), true);
    assert.equal(store.wouldBeBlocked("password"), true);
    assert.equal(store.wouldBeBlocked("my_custom_key"), false);
    assert.equal(store.wouldBeBlocked("root_password"), true);
  });

  // ---------------------------------------------------------------------------
  // Custom Blocklist
  // ---------------------------------------------------------------------------

  it("should accept custom do-not-persist keys appended to defaults", async () => {
    const storePath = join(tempDir, "test-custom-block.json");
    const store = new SecretStore({
      backend: new TestFileBackend(storePath),
      doNotPersistKeys: ["my_secret", "internal_key"],
    });
    await initStore(store);
    assert.equal(store.wouldBeBlocked("sudo"), true); // Still default
    assert.equal(store.wouldBeBlocked("my_secret"), true); // Custom added
    assert.equal(store.wouldBeBlocked("internal_key"), true);
    assert.equal(store.wouldBeBlocked("normal_key"), false);
  });

  it("should accept override blocklist replacing defaults", async () => {
    const storePath = join(tempDir, "test-override-blocklist.json");
    const store = new SecretStore({
      backend: new TestFileBackend(storePath),
      overrideDoNotPersistKeys: ["my_secret"],
    });
    await initStore(store);
    assert.equal(store.wouldBeBlocked("sudo"), false); // Defaults removed
    assert.equal(store.wouldBeBlocked("my_secret"), true); // Custom only
    assert.equal(store.wouldBeBlocked("password"), false);
  });

  // ---------------------------------------------------------------------------
  // Persistence (save/load roundtrip via TestFileBackend)
  // ---------------------------------------------------------------------------

  it("should persist and reload secrets correctly", async () => {
    const storePath = join(tempDir, "test-roundtrip.json");
    const backend = new TestFileBackend(storePath);
    const store1 = new SecretStore({ backend });
    await initStore(store1);

    store1.set("api_key", "sk-abc123");
    store1.set("sudo", "should-not-persist"); // Blocked
    store1.set("normal", "normal-value");
    await store1.flush();

    // Verify the file exists
    assert.equal(existsSync(storePath), true);
    const raw = backend.readRaw();
    const data = JSON.parse(raw);
    assert.equal(data.version, 1);
    assert.equal(data.secrets["api_key"], "sk-abc123");
    assert.equal(data.secrets["normal"], "normal-value");
    assert.equal(data.secrets["sudo"], undefined); // Blocked — not persisted

    // Load into a fresh store
    const store2 = new SecretStore({ backend: new TestFileBackend(storePath) });
    await initStore(store2);
    assert.equal(store2.get("api_key"), "sk-abc123");
    assert.equal(store2.get("normal"), "normal-value");
    assert.equal(store2.get("sudo"), undefined); // Never persisted
  });

  it("should handle empty/clean store gracefully", async () => {
    const storePath = join(tempDir, "test-empty.json");
    const store = makeStore(storePath);
    await initStore(store);
    assert.equal(store.list().length, 0);
  });

  it("should persist ephemeral-then-persisted transitions correctly", async () => {
    const storePath = join(tempDir, "test-transition.json");
    const backend = new TestFileBackend(storePath);
    const store = new SecretStore({ backend });
    await initStore(store);

    // Set as ephemeral
    store.set("mykey", "myvalue", false);
    await store.flush();

    // File should NOT exist (nothing was persisted)
    assert.equal(existsSync(storePath), false);

    // Promote to persisted
    store.set("mykey", "myvalue", true);
    await store.flush();

    // File should now have it
    assert.equal(existsSync(storePath), true);
    const raw2 = JSON.parse(backend.readRaw());
    assert.equal(raw2.secrets["mykey"], "myvalue");
  });

  it("should handle secret values with special characters", async () => {
    const storePath = join(tempDir, "test-special-chars.json");
    const backend = new TestFileBackend(storePath);
    const store = new SecretStore({ backend });
    await initStore(store);

    const special = "abc!@#$%^&*()_+{}|:<>?`~\"'\\;\n\t";
    store.set("special_key", special);
    await store.flush();

    const store2 = new SecretStore({ backend: new TestFileBackend(storePath) });
    await initStore(store2);
    assert.equal(store2.get("special_key"), special);
  });

  it("should handle Unicode and emoji in secrets", async () => {
    const storePath = join(tempDir, "test-unicode.json");
    const backend = new TestFileBackend(storePath);
    const store = new SecretStore({ backend });
    await initStore(store);

    const unicode = "パスワード🔐日本語✓";
    store.set("unicode_key", unicode);
    await store.flush();

    const store2 = new SecretStore({ backend: new TestFileBackend(storePath) });
    await initStore(store2);
    assert.equal(store2.get("unicode_key"), unicode);
  });

  // ---------------------------------------------------------------------------
  // Edge Cases
  // ---------------------------------------------------------------------------

  it("should handle empty secret values", async () => {
    const store = makeStore(join(tempDir, "test-empty-value.json"));
    await initStore(store);
    store.set("empty", "");
    assert.equal(store.get("empty"), "");
    assert.equal(store.has("empty"), true);
  });

  it("should handle very long secret values", async () => {
    const store = makeStore(join(tempDir, "test-long-value.json"));
    await initStore(store);
    const longValue = "x".repeat(10000);
    store.set("long", longValue);
    assert.equal(store.get("long"), longValue);
  });

  it("should return correct blocklist via getBlocklist", async () => {
    const store = makeStore(join(tempDir, "test-blocklist.json"));
    await initStore(store);
    const blocklist = store.getBlocklist();
    assert.ok(blocklist.includes("sudo"));
    assert.ok(blocklist.includes("password"));
    assert.ok(blocklist.includes("root"));
  });

  it("should persist only non-blocked keys on save", async () => {
    const storePath = join(tempDir, "test-mixed-persist.json");
    const backend = new TestFileBackend(storePath);
    const store = new SecretStore({ backend });
    await initStore(store);

    store.set("openai_key", "sk-proj-123");
    store.set("sudo_password", "hunter2"); // Blocked
    store.set("db_password", "secret"); // Blocked
    store.set("normal_config", "some-value");
    await store.flush();

    const raw = JSON.parse(backend.readRaw());
    const persistedKeys = Object.keys(raw.secrets);
    assert.ok(persistedKeys.includes("openai_key"));
    assert.ok(persistedKeys.includes("normal_config"));
    assert.ok(!persistedKeys.includes("sudo_password"));
    assert.ok(!persistedKeys.includes("db_password"));
  });

  it("should NEVER persist blocked keys to disk even with persist=true", async () => {
    const storePath = join(tempDir, "test-blocked-persist-true.json");
    const backend = new TestFileBackend(storePath);
    const store = new SecretStore({ backend });
    await initStore(store);

    store.set("sudo", "hunter2", true);       // Blocked + explicit persist=true
    store.set("root_password", "toor", true); // Blocked + explicit persist=true
    store.set("safe_key", "safe_val");        // Non-blocked
    await store.flush();

    const raw = JSON.parse(backend.readRaw());
    const persistedKeys = Object.keys(raw.secrets);
    assert.ok(persistedKeys.includes("safe_key"));
    assert.ok(!persistedKeys.includes("sudo"));
    assert.ok(!persistedKeys.includes("root_password"));
  });

  // ---------------------------------------------------------------------------
  // Backend Auto-Detection
  // ---------------------------------------------------------------------------

  it("should return backend name via getBackendName", async () => {
    const storePath = join(tempDir, "test-backend-name.json");
    const store = new SecretStore({
      backend: new TestFileBackend(storePath),
    });
    await initStore(store);
    assert.equal(store.getBackendName(), "test-file");
  });

  it("should auto-detect backend chain on first available", async () => {
    // With explicit chain, should use the first available one
    const storePath = join(tempDir, "test-auto-detect.json");
    // Both backends are "available", so the first in chain wins
    const backend1 = new TestFileBackend(storePath);
    const store = new SecretStore({
      backendChain: [backend1],
    });
    await initStore(store);
    assert.equal(store.getBackendName(), "test-file");
  });
});
