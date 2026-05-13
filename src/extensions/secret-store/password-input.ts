/**
 * PasswordInput — masked text input component for pi's custom TUI.
 *
 * Renders a one-line input where all characters are displayed as `•`.
 * Used by the ask_secret tool to avoid leaking secrets on screen.
 *
 * Key bindings:
 *   - Regular characters: append masked
 *   - Backspace: delete last character
 *   - Ctrl+U: clear entire input
 *   - Enter: submit (returns the value)
 *   - Escape: cancel (returns undefined)
 */

import type { Component, Focusable } from "@earendil-works/pi-tui";
import { matchesKey, Key } from "@earendil-works/pi-tui";

// =============================================================================
// Constants
// =============================================================================

const MASK_CHAR = "•";
const PADDING_X = 2;
const PADDING_Y = 1;

// =============================================================================
// PasswordInput Component
// =============================================================================

export interface PasswordInputOptions {
  /** Prompt text shown above the input line */
  prompt: string;
  /** Called when user presses Enter with the entered value */
  onSubmit?: (value: string) => void;
  /** Called when user presses Escape */
  onCancel?: () => void;
}

export class PasswordInput implements Component, Focusable {
  private value = "";
  private cursor = 0; // character position, not screen position
  private readonly prompt: string;
  public focused = false;
  public onSubmit?: (value: string) => void;
  public onCancel?: () => void;

  constructor(options: PasswordInputOptions) {
    this.prompt = options.prompt;
    this.onSubmit = options.onSubmit;
    this.onCancel = options.onCancel;
  }

  /** Get the current (unmasked) value */
  getValue(): string {
    return this.value;
  }

  /** Reset the input to empty */
  clear(): void {
    this.value = "";
    this.cursor = 0;
  }

  // ===========================================================================
  // Component Interface
  // ===========================================================================

  invalidate(): void {
    // No cached state to invalidate
  }

  render(width: number): string[] {
    const lines: string[] = [];

    // Top padding
    for (let i = 0; i < PADDING_Y; i++) {
      lines.push(" ".repeat(width));
    }

    // Prompt line
    lines.push(" " + this.prompt);

    // Input line — show masked chars with cursor position
    const masked = MASK_CHAR.repeat(this.value.length);
    const inputLine = "> " + masked;

    // Pad/truncate to width
    const display = inputLine.length < width
      ? inputLine + " ".repeat(width - inputLine.length)
      : inputLine.slice(0, width);

    lines.push(display);

    // Bottom padding
    for (let i = 0; i < PADDING_Y; i++) {
      lines.push(" ".repeat(width));
    }

    return lines;
  }

  // ===========================================================================
  // Keyboard Input
  // ===========================================================================

  handleInput(data: string): void {
    // Enter — submit
    if (matchesKey(data, Key.enter)) {
      this.onSubmit?.(this.value);
      return;
    }

    // Escape — cancel
    if (matchesKey(data, Key.escape)) {
      this.onCancel?.();
      return;
    }

    // Backspace — delete last char
    if (matchesKey(data, Key.backspace)) {
      if (this.cursor > 0) {
        this.value = this.value.slice(0, this.cursor - 1) + this.value.slice(this.cursor);
        this.cursor--;
      }
      return;
    }

    // Ctrl+U — clear entire input
    if (matchesKey(data, Key.ctrl("u"))) {
      this.value = "";
      this.cursor = 0;
      return;
    }

    // Ctrl+C or Ctrl+D — ignore (let pi handle abort)
    if (matchesKey(data, Key.ctrl("c")) || matchesKey(data, Key.ctrl("d"))) {
      return;
    }

    // Regular character — single printable character
    if (data.length === 1 && data.charCodeAt(0) >= 0x20 && data.charCodeAt(0) <= 0x7e) {
      this.value = this.value.slice(0, this.cursor) + data + this.value.slice(this.cursor);
      this.cursor++;
      return;
    }

    // Arrow keys — ignore in password mode (keep cursor at end)
    if (matchesKey(data, Key.left) || matchesKey(data, Key.right)) {
      return;
    }

    // Ctrl+W — delete last word (anything trailing a non-alnum char)
    if (matchesKey(data, Key.ctrl("w"))) {
      const before = this.value.slice(0, this.cursor);
      const after = this.value.slice(this.cursor);
      const trimmed = before.replace(/[^\s]+[\s]*$/, "");
      this.value = trimmed + after;
      this.cursor = trimmed.length;
      return;
    }
  }
}
