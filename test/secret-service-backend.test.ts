/**
 * Regression tests for SecretServiceBackend.
 *
 * The original bug: secret-tool expects the secret value via stdin, not as
 * a CLI argument. The first implementation passed the value as a CLI arg,
 * which caused "must specify attributes and values in pairs" errors.
 *
 * Additional bug: secret-tool outputs `attribute.*` metadata lines on stderr,
 * not stdout, so list() was parsing the wrong stream.
 *
 * These tests verify the fixes by roundtripping values through secret-tool.
 * They only run the full integration tests if secret-tool is available.
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { SecretServiceBackend } from "../src/extensions/secret-store/backends/secret-service-backend.js";

describe("SecretServiceBackend", () => {
  let available = false;

  before(async () => {
    const backend = new SecretServiceBackend();
    available = await backend.isAvailable();
  });

  it("should report availability correctly", async () => {
    const backend = new SecretServiceBackend();
    const result = await backend.isAvailable();
    assert.equal(typeof result, "boolean");
  });

  // Wrapper that silently skips tests when secret-tool isn't installed.
  // We can't use `{ skip: ... }` because it's evaluated at definition time
  // before `before` sets `available`. Instead, each test checks at runtime.
  function itIfAvailable(name: string, fn: (backend: SecretServiceBackend) => Promise<void>) {
    it(name, async () => {
      if (!available) return; // silently skip when no secret-tool
      const backend = new SecretServiceBackend();
      await fn(backend);
    });
  }

  itIfAvailable("should store and retrieve a simple value", async (b) => {
    const key = "test-simple-" + Date.now();
    try {
      await b.set(key, "hello-world");
      assert.equal(await b.get(key), "hello-world");
    } finally {
      await b.delete(key).catch(() => {});
    }
  });

  itIfAvailable("should store and retrieve a value with special characters", async (b) => {
    const key = "test-special-" + Date.now();
    const special = "abc!@#$%^&*()_+{}|:<>?`~\"'\\;\n\t";
    try {
      await b.set(key, special);
      assert.equal(await b.get(key), special);
    } finally {
      await b.delete(key).catch(() => {});
    }
  });

  itIfAvailable("should store and retrieve a value with spaces", async (b) => {
    const key = "test-spaces-" + Date.now();
    const withSpaces = "this has spaces and  multiple   spaces";
    try {
      await b.set(key, withSpaces);
      assert.equal(await b.get(key), withSpaces);
    } finally {
      await b.delete(key).catch(() => {});
    }
  });

  itIfAvailable("should store and retrieve a very long value", async (b) => {
    const key = "test-long-" + Date.now();
    const long = "x".repeat(5000);
    try {
      await b.set(key, long);
      const got = await b.get(key);
      assert.equal(got, long);
      assert.equal(got!.length, 5000);
    } finally {
      await b.delete(key).catch(() => {});
    }
  });

  itIfAvailable("should store and retrieve unicode and emoji", async (b) => {
    const key = "test-unicode-" + Date.now();
    const unicode = "パスワード🔐日本語✓";
    try {
      await b.set(key, unicode);
      assert.equal(await b.get(key), unicode);
    } finally {
      await b.delete(key).catch(() => {});
    }
  });

  itIfAvailable("should return undefined for nonexistent key", async (b) => {
    const value = await b.get("nonexistent-" + Date.now());
    assert.equal(value, undefined);
  });

  itIfAvailable("should delete an existing key and return true", async (b) => {
    const key = "test-delete-" + Date.now();
    await b.set(key, "delete-me");
    assert.equal(await b.delete(key), true);
    assert.equal(await b.get(key), undefined);
  });

  itIfAvailable("should list stored keys", async (b) => {
    const key1 = "test-list-a-" + Date.now();
    const key2 = "test-list-b-" + Date.now();
    try {
      await b.set(key1, "value1");
      await b.set(key2, "value2");
      const keys = await b.list();
      assert.ok(keys.includes(key1), `keys should include ${key1}, got ${JSON.stringify(keys)}`);
      assert.ok(keys.includes(key2), `keys should include ${key2}, got ${JSON.stringify(keys)}`);
    } finally {
      await b.delete(key1).catch(() => {});
      await b.delete(key2).catch(() => {});
    }
  });

  itIfAvailable("should return false when deleting a nonexistent key", async (b) => {
    // secret-tool clear on a key that was never stored exits non-zero,
    // so delete() catches the error and returns false.
    const result = await b.delete("nonexistent-" + Date.now());
    assert.equal(result, false);
  });

  itIfAvailable("should store then list then delete roundtrip", async (b) => {
    // Full regression: this failed before because list() parsed stdout
    // while secret-tool outputs attribute lines on stderr.
    const key = "test-roundtrip-" + Date.now();
    await b.set(key, "roundtrip-value");
    const list = await b.list();
    assert.ok(list.includes(key), `list should contain key, got ${JSON.stringify(list)}`);
    await b.delete(key);
    const after = await b.get(key);
    assert.equal(after, undefined);
  });
});
