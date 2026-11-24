/**
 * Admission of each tool call under the execution's ceiling, and the target's identity hook.
 *
 * A slot is reserved and announced before identity, the tool or its dry-run value. The call
 * that reaches the ceiling is admitted and announced first; every later call is refused without
 * changing the count, even when the target catches the error and keeps trying.
 */

import { ChannelError, channelFor } from "./channel.js";
import { GazuaBlockedError } from "./errors.js";
import type { Session } from "./session.js";

export const CEILING_REASON = "tool_call_ceiling";

const admitted = new Map<string, number>();
const latched = new Set<string>();

/** Reserves one tool call slot or throws `GazuaBlockedError`. */
export function admit(session: Session): void {
  const execution = session.execution;
  if (execution === null) {
    return;
  }
  const key = execution.executionId;
  if (latched.has(key)) {
    throw new GazuaBlockedError(CEILING_REASON);
  }
  const count = (admitted.get(key) ?? 0) + 1;
  const reached = count >= execution.maxToolCalls;
  const channel = channelFor(execution);
  try {
    channel.emit("tool_call_admitted", { count }, reached);
    if (reached) {
      channel.emit(CEILING_REASON, { count }, true);
    }
  } catch (error) {
    if (error instanceof ChannelError) {
      throw new GazuaBlockedError("execution_channel_unavailable");
    }
    throw error;
  }
  admitted.set(key, count);
  if (reached) {
    latched.add(key);
  }
}

export function resetAdmissions(): void {
  admitted.clear();
  latched.clear();
}

/**
 * Runs `invoke` as the given user. It must call `invoke` once and restore its own identity
 * afterwards, also when `invoke` throws.
 */
export type AsUserHook = <T>(actorId: string, invoke: () => T) => T | Promise<T>;

let identityHook: AsUserHook | null = null;

/** Installed by the runner from the target's declared export. Not part of the public API. */
export function setIdentityHook(hook: AsUserHook | null): void {
  identityHook = hook;
}

export function currentIdentityHook(): AsUserHook | null {
  return identityHook;
}
