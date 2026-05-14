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
 * - Custom regex templates for non-standard formats
 */

import { basename, dirname, resolve } from "node:path";

// =============================================================================
// Types
// =============================================================================

/**
 * A custom template for parsing non-standard credential file formats.
 *
 * Uses a regex with named capture groups to extract key-value pairs.
 *
 * @example
 * ```ts
 * {
 *   name: "netrc-like",
 *   description: "netrc-style machine/login/password",
 *   pattern: "^machine\\s+(?<key>\\S+)\\s*\\n\\s+login\\s+(?<login>\\S+)\\s*\\n\\s+password\\s+(?<value>\\S+)"",
 *   flags: "gm",
 *   keyGroup: "key",
 *   valueGroup: "value"
 * }
 * ```
 */
export interface CredentialTemplate {
  name: string;
  description: string;
  /** Regex pattern with named capture groups */
  pattern: string;
  /** Regex flags (default: "gm") */
  flags?: string;
  /** Named group for the credential key (default: "key") */
  keyGroup?: string;
  /** Named group for the credential value (default: "value") */
  valueGroup?: string;
  /** Optional file glob pattern for auto-detection */
  filePattern?: string;
  /** Optional regex for lines to skip before matching */
  skipPattern?: string;
}

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
    let value = stripQuotes(trimmed.slice(eqIdx + 1).trim());

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
    let value = stripQuotes(trimmed.slice(sepIdx + 1).trim());

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
/**
 * Strip matching surrounding quotes from a string.
 * Handles both single and double quotes. Returns the stripped value
 * if quotes match, or the original value unchanged.
 */
export function stripQuotes(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

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

// =============================================================================
// Custom template parser
// =============================================================================

/**
 * Result from a custom template parse, including any warnings
 * (e.g. invalid regex patterns that were skipped).
 */
export interface TemplateParseResult {
  entries: Array<{ key: string; value: string }>;
  warnings: string[];
}

/**
 * Parse credential file content using a custom regex template.
 *
 * The template's pattern is applied globally across the content.
 * Each match extracts the credential key (from `keyGroup`, default "key")
 * and value (from `valueGroup`, default "value") from named capture groups.
 *
 * Optionally skips lines matching `skipPattern` before matching.
 *
 * Returns both the matched entries and any warnings (invalid sub-patterns,
 * skipped configurations, etc.).
 */
export function parseWithTemplate(
  content: string,
  template: CredentialTemplate
): TemplateParseResult {
  const result: TemplateParseResult = { entries: [], warnings: [] };

  // Apply skip filter if provided
  let text = content;
  if (template.skipPattern) {
    try {
      const skipRe = new RegExp(template.skipPattern, "gm");
      text = text.replace(skipRe, "");
    } catch (e: any) {
      result.warnings.push(`Invalid skip pattern "${template.skipPattern}": ${e.message}`);
    }
  }

  const flags = template.flags ?? "gm";
  const keyGroup = template.keyGroup ?? "key";
  const valueGroup = template.valueGroup ?? "value";

  try {
    const re = new RegExp(template.pattern, flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      const groups = match.groups ?? {};
      const key = (groups[keyGroup] ?? "").trim();
      const value = stripQuotes((groups[valueGroup] ?? "").trim());
      if (!key) continue;
      result.entries.push({ key, value });

      // Avoid infinite loop on zero-length matches
      if (match.index === re.lastIndex) re.lastIndex++;
    }
  } catch (e: any) {
    result.warnings.push(`Invalid template pattern: ${e.message}`);
  }

  return result;
}
