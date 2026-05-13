/**
 * SecretBackend — pluggable storage backend interface.
 *
 * Each backend stores key/value pairs in a platform-native secure store:
 *   Linux   → Secret Service (libsecret/secret-tool)
 *   macOS   → Keychain (security CLI)
 *   Windows → Credential Manager (PowerShell)
 *   Any OS  → Encrypted file (AES-256-GCM, universal fallback)
 *
 * Users can implement custom backends by implementing this interface
 * and registering them via SecretStoreOptions.
 */

export interface SecretBackend {
  /** Human-readable name for debugging / status display */
  readonly name: string;

  /** Check whether this backend is available on the current system */
  isAvailable(): Promise<boolean>;

  /** Retrieve a secret by key. Returns undefined if not found. */
  get(key: string): Promise<string | undefined>;

  /** Store a secret. Overwrites any existing value for the same key. */
  set(key: string, value: string): Promise<void>;

  /** Delete a secret. Returns true if it existed, false otherwise. */
  delete(key: string): Promise<boolean>;

  /** List all stored secret keys (empty array if none). */
  list(): Promise<string[]>;
}
