/**
 * Private capture of tool returns next to the call log, in the format the Python engine reads.
 *
 * Only plain JSON data is captured; nothing of the target's objects is called to make a value
 * serializable. A capture that cannot be written never changes what the tool returns, and the
 * reader treats the missing line as incomplete evidence.
 */

import { existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { appendLine } from "./channel.js";
import { asciiJson, nativeJson, Opaque } from "./json.js";
import type { Session } from "./session.js";

export const RETURNS_FILE = "returns.private.jsonl";
export const MAX_OBSERVATION_BYTES = 64 * 1024;
export const MAX_EXECUTION_BYTES = 1024 * 1024;

export class ReturnSidecar {
  private written: number | null = null;

  constructor(readonly path: string) {}

  private size(): number {
    if (this.written === null) {
      this.written = existsSync(this.path) ? statSync(this.path).size : 0;
    }
    return this.written;
  }

  record(executionId: string, seq: number, original: unknown, delivered: unknown): void {
    const head = { schema_version: 1, kind: "tool_return", execution_id: executionId };
    let line = "";
    let reason: string | null = null;
    try {
      line = asciiJson({ ...head, call_seq: seq, original: nativeJson(original), delivered: nativeJson(delivered) });
      if (line.length > MAX_OBSERVATION_BYTES) {
        reason = "too_large";
      }
    } catch (error) {
      if (!(error instanceof Opaque) && !(error instanceof RangeError)) {
        throw error;
      }
      reason = "not_serializable";
    }
    try {
      if (reason === null && this.size() + line.length + 1 > MAX_EXECUTION_BYTES) {
        reason = "execution_limit";
      }
      if (reason !== null) {
        line = asciiJson({ ...head, call_seq: seq, unavailable_reason: reason });
      }
      appendLine(this.path, `${line}\n`);
      this.written = this.size() + line.length + 1;
    } catch {
      // The reader sees a returned call without its line and treats it as missing.
    }
  }
}

const sidecars = new Map<string, ReturnSidecar>();

/** Writes the return of call `seq`. Never throws into the tool's caller. */
export function recordReturn(session: Session, seq: number, original: unknown, delivered: unknown): void {
  if (session.execution === null) {
    return;
  }
  const key = resolve(join(dirname(session.callLog), RETURNS_FILE));
  let sidecar = sidecars.get(key);
  if (sidecar === undefined) {
    sidecar = new ReturnSidecar(key);
    sidecars.set(key, sidecar);
  }
  try {
    sidecar.record(session.execution.executionId, seq, original, delivered);
  } catch {
    // A capture failure leaves the evidence incomplete; the tool's result is unchanged.
  }
}

export function clearSidecars(): void {
  sidecars.clear();
}
