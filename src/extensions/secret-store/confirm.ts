/**
 * Confirmation helper for destructive secret-store operations.
 *
 * Uses the built-in ctx.ui.input() dialog (well-tested, proper sizing)
 * instead of a custom TUI component, which had rendering issues with
 * long confirmation phrases on narrow terminals.
 */

import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

/**
 * Prompt the user to type a confirmation string before a destructive action.
 *
 * @param ctx - Extension context (for ui.input)
 * @param prompt - Message shown to the user describing what to type
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

  const typed = await ctx.ui.input(prompt, "");
  return typed === expected;
}
