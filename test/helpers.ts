/**
 * Test backends for SecretStore tests.
 * Plain JSON file backend — unencrypted, direct file reads for assertion.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { SecretBackend } from "../src/extensions/secret-store/backends/interface.js";

/**
 * Plain JSON file backend for testing.
 * Writes unencrypted JSON so tests can read the file directly.
 */
export class TestFileBackend implements SecretBackend {
  readonly name = "test-file";
  private filePath: string;
  private data: Record<string, string> = {};

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async get(key: string): Promise<string | undefined> {
    await this.ensureLoaded();
    return this.data[key];
  }

  async set(key: string, value: string): Promise<void> {
    await this.ensureLoaded();
    this.data[key] = value;
    await this.persist();
  }

  async delete(key: string): Promise<boolean> {
    await this.ensureLoaded();
    if (!(key in this.data)) return false;
    delete this.data[key];
    await this.persist();
    return true;
  }

  async list(): Promise<string[]> {
    await this.ensureLoaded();
    return Object.keys(this.data);
  }

  private async ensureLoaded(): Promise<void> {
    if (Object.keys(this.data).length > 0) return;
    try {
      const raw = await readFile(this.filePath, "utf-8");
      this.data = JSON.parse(raw).secrets ?? {};
    } catch {
      this.data = {};
    }
  }

  private async persist(): Promise<void> {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true, mode: 0o700 });
    }
    const content = JSON.stringify({ version: 1, secrets: this.data }, null, 2);
    await writeFile(this.filePath, content, { mode: 0o600, encoding: "utf-8" });
  }

  /** Read the raw file content for assertions */
  readRaw(): string {
    return readFileSync(this.filePath, "utf-8");
  }
}
