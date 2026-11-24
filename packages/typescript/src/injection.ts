/**
 * Delivery of attack text through textual tool results.
 *
 * The text is appended as data. A result that is not text is left untouched and recorded as
 * not delivered, so the attack is reported as not tested. While the runner has armed one
 * injection for a turn, no other one can be chosen.
 */

import type { Injection, Session } from "./session.js";

export interface InjectionRecord {
  readonly id: string;
  readonly delivered: boolean;
  readonly reason: string | null;
}

const deliveries = new Map<string, number>();
let armed: string | null = null;

function key(session: Session, injection: Injection): string {
  return `${session.runId}\u0000${injection.id}`;
}

function pending(session: Session, tool: string): Injection | null {
  for (const injection of session.injections) {
    if (injection.tool !== tool || (armed !== null && injection.id !== armed)) {
      continue;
    }
    if ((deliveries.get(key(session, injection)) ?? 0) < injection.maxDeliveries) {
      return injection;
    }
  }
  return null;
}

/** Only `injectionId` can be delivered until `disarm`. Reserved to the runner. */
export function arm(injectionId: string | null): void {
  armed = injectionId;
}

export function disarm(): void {
  armed = null;
}

/** The result with the pending injection for this tool, and what goes to the log. */
export function inject(session: Session, tool: string, result: unknown): [unknown, InjectionRecord | null] {
  const injection = pending(session, tool);
  if (injection === null) {
    return [result, null];
  }
  if (typeof result !== "string") {
    return [result, { id: injection.id, delivered: false, reason: "unsupported_result_type" }];
  }
  const counted = key(session, injection);
  deliveries.set(counted, (deliveries.get(counted) ?? 0) + 1);
  return [`${result}\n${injection.text}`, { id: injection.id, delivered: true, reason: null }];
}

export function resetDeliveries(): void {
  deliveries.clear();
  armed = null;
}
