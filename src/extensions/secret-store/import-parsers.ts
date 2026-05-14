/**
 * Credential file parsers for import_secret.
 *
 * Extracted from the extension entry point so they can be unit-tested
 * independently of the pi extension lifecycle.
 *
 * Supported formats:
 * - .env (KEY=VALUE with # comments)
 * - .json (flat objects with string values)
 * - INI-like ([sections], key=value, # and ; comments)
 */

import { basename, dirname, resolve } from "node:path";

// =============================================================================
// Format detection
// =============================================================================

/**
 * Detect credential file format from its path.
 *
 * Returns "env" for .env / .env.* files, "json" for .json files,
 * and "ini" for everything else (e.g. ~/.aws/credentials).
 */
export function detectFormat(filePath: string): "env" | "json" | "ini" {
  const name = basename(filePath);
  if (name === ".env" || name.startsWith(".env.")) return "env";
  if (name.endsWith(".json")) return "json";
  return "ini";
}

// =============================================================================
// .env parser
// =============================================================================

/**
 * Parse .env file content into key-value pairs.
 *
 * Handles:
 * - KEY=VALUE lines
 * - Single and double quoted values (stripped)
 * - # comments (full-line only)
 * - Blank lines (skipped)
 */
export function parseEnv(
  content: string
): Array<{ key: string; value: string }> {
  const result: Array<{ key: string; value: string }> = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();

    // Strip surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key) result.push({ key, value });
  }
  return result;
}

// =============================================================================
// JSON parser
// =============================================================================

/**
 * Parse JSON credential file into key-value pairs.
 *
 * Only extracts top-level string values. Nested objects, arrays,
 * numbers, booleans, and null are silently skipped.
 */
export function parseJson(
  content: string
): Array<{ key: string; value: string }> {
  const result: Array<{ key: string; value: string }> = [];
  try {
    const data = JSON.parse(content);
    if (typeof data !== "object" || data === null || Array.isArray(data))
      return result;
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string" && value.length > 0) {
        result.push({ key, value });
      }
    }
  } catch {
    // Invalid JSON — return empty
  }
  return result;
}

// =============================================================================
// INI parser
// =============================================================================

/**
 * Parse INI-like credential file into key-value pairs.
 *
 * Handles:
 * - [section] headers — prepended as "section:key"
 * - key=value and key: value separators
 * - # and ; comments (full-line only)
 * - Single and double quoted values (stripped)
 * - Blank lines (skipped)
 *
 * Values outside any [section] get no prefix.
 */
export function parseIni(
  content: string
): Array<{ key: string; value: string }> {
  const result: Array<{ key: string; value: string }> = [];
  let currentSection = "";

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";"))
      continue;

    // Section header
    const sectionMatch = trimmed.match(/^\s*\[([^\]]+)\]\s*$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      continue;
    }

    // key = value or key: value
    const sepIdx = trimmed.search(/[=:]/);
    if (sepIdx === -1) continue;

    const key = trimmed.slice(0, sepIdx).trim();
    let value = trimmed.slice(sepIdx + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!key) continue;

    const fullKey = currentSection ? `${currentSection}:${key}` : key;
    result.push({ key: fullKey, value });
  }

  return result;
}

// =============================================================================
// Namespace derivation
// =============================================================================

/**
 * Derive a secret-store namespace from a file path.
 *
 * Uses the parent directory's basename as the namespace.
 *
 * Examples:
 *   ~/.aws/credentials       → "aws"
 *   /projects/my-app/.env    → "my-app"
 *   /home/user/config.json   → "config"
 */
export function deriveNamespace(filePath: string): string {
  const expanded = filePath.replace(
    /^~/,
    process.env.HOME || "~"
  );
  let name = basename(dirname(resolve(expanded)));
  // Strip leading dot from hidden directories (.aws → aws)
  if (name.startsWith(".")) name = name.slice(1);
  return name;
}
