/**
 * Optional signals from the tested agent: incremental usage cost, rate limits and a refused
 * credential. Gazua never sees the agent's model calls, never reads credentials and opens no
 * connection; these are the only ways it learns about them.
 */

import { randomUUID } from "node:crypto";

import { ChannelError, channelFor } from "./channel.js";
import { sessionState } from "./session.js";

/** The largest wait, in seconds, that a rate limit can ask for. */
export const MAX_RETRY_AFTER = 3600;

function finiteNonNegative(value: unknown, name: string): number {
  if (typeof value !== "number") {
    throw new TypeError(`${name} must be a number.`);
  }
  if (!Number.isFinite(value)) {
    throw new RangeError(`${name} must be finite.`);
  }
  if (value < 0) {
    throw new RangeError(`${name} must not be negative.`);
  }
  return value;
}

/**
 * Throw from the test entrypoint when the model provider answered 429. `retryAfter` is the
 * wait in seconds the provider asked for, when it said one. Gazua recognizes a rate limit only
 * through this class, never by reading error messages.
 */
export class GazuaRateLimited extends Error {
  readonly retryAfter: number | null;

  constructor(retryAfter?: number | null) {
    super("The target reported a rate limit (429).");
    this.name = "GazuaRateLimited";
    this.retryAfter =
      retryAfter === undefined || retryAfter === null
        ? null
        : Math.min(finiteNonNegative(retryAfter, "retryAfter"), MAX_RETRY_AFTER);
  }
}

/**
 * Throw from the test entrypoint when the agent's model provider refused its credential. It
 * carries no key, no provider object and no message from the provider; the run stops instead
 * of trying again.
 */
export class GazuaAuthenticationError extends Error {
  constructor() {
    super("The agent could not authenticate with its model provider.");
    this.name = "GazuaAuthenticationError";
  }
}

/**
 * Reports the cost in USD of the model calls made since the previous report. Each call adds an
 * increment; never pass a running total. Returns true when the cost reached the supervisor and
 * false outside a supervised execution, where the call does nothing.
 */
export function reportUsage(usage: { readonly costUsd: number }): boolean {
  const value = finiteNonNegative(usage.costUsd, "costUsd");
  const state = sessionState();
  if (state === null || state.kind === "invalid" || state.execution === null) {
    return false;
  }
  try {
    channelFor(state.execution).emit(
      "usage",
      { usage_id: randomUUID().replaceAll("-", ""), cost_usd: String(value) },
      true,
    );
  } catch (error) {
    if (error instanceof ChannelError) {
      return false;
    }
    throw error;
  }
  return true;
}
