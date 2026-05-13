/**
 * Confirmation helper for destructive secret-store operations.
 *
 * Uses ctx.ui.custom() (same mechanism as PasswordInput) to prompt the user
 * to type a confirmation string before allowing deletion. This prevents
 * accidental secret deletion by the agent.
 */

import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { matchesKey, Key } from "@earendil-works/pi-tui";

// =============================================================================
// Simple Input Component (unmasked, one-liner)
// =============================================================================

/**
 * A minimal single-line text input component for confirmation prompts.
 * Unlike PasswordInput, this shows the typed characters so the user can
 * verify they typed the correct confirmation string.
 */
class ConfirmInput {
  private value = "";
  private readonly prompt: string;
  private readonly expected: string;
  public onSubmit?: (ok: boolean) => void;

  constructor(prompt: string, expected: string) {
    this.prompt = prompt;
    this.expected = expected;
  }

  render(width: number): string[] {
    const lines: string[] = [];
    // Blank line for spacing
    lines.push(" ".repeat(width));
    // Prompt line
    lines.push(" " + this.prompt);
    // Input line with cursor indicator
    const display = "> " + this.value + (this.value.length < this.expected.length ? "▊" : " ");
    lines.push(display.length < width ? display + " ".repeat(width - display.length) : display.slice(0, width));
    // Hint line
    const hint = `  (type the secret name above to confirm)`;
    lines.push(hint.length < width ? hint + " ".repeat(width - hint.length) : hint.slice(0, width));
    // Blank line
    lines.push(" ".repeat(width));
    return lines;
  }

  handleInput(data: string): void {
    // Enter — confirm if value matches expected
    if (matchesKey(data, Key.enter)) {
      this.onSubmit?.(this.value === this.expected);
      return;
    }

    // Escape — cancel
    if (matchesKey(data, Key.escape)) {
      this.onSubmit?.(false);
      return;
    }

    // Backspace
    if (matchesKey(data, Key.backspace)) {
      this.value = this.value.slice(0, -1);
      return;
    }

    // Ctrl+U — clear
    if (matchesKey(data, Key.ctrl("u"))) {
      this.value = "";
      return;
    }

    // Ctrl+C / Ctrl+D — ignore (let pi handle abort)
    if (matchesKey(data, Key.ctrl("c")) || matchesKey(data, Key.ctrl("d"))) {
      return;
    }

    // Printable character
    if (data.length === 1 && data.charCodeAt(0) >= 0x20 && data.charCodeAt(0) <= 0x7e) {
      this.value += data;
    }
  }

  invalidate(): void {
    // no cache
  }
}

// =============================================================================
// Reusable Confirmation Helper
// =============================================================================

/**
 * Prompt the user to type a confirmation string before a destructive action.
 *
 * @param ctx - Extension context (for ui.custom)
 * @param prompt - Message shown to the user (e.g., "Type the secret name to confirm deletion")
 * @param expected - The exact string the user must type to confirm
 * @returns true if the user typed the expected string and pressed Enter, false otherwise
 */
export async function confirmDestructiveAction(
  ctx: ExtensionContext,
  prompt: string,
  expected: string
): Promise<boolean> {
  if (!ctx.hasUI) {
    // In non-interactive mode, we can't confirm — err on the side of safety
    return false;
  }

  const confirmed = await ctx.ui.custom<boolean>(
    (_tui, _theme, _keybindings, done) => {
      const input = new ConfirmInput(prompt, expected);
      input.onSubmit = (ok) => done(ok);
      return input;
    },
    { overlay: true }
  );

  return confirmed === true;
}
