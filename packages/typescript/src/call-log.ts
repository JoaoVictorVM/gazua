/**
 * Append-only JSONL log of tool calls, version 1, the evidence that verdicts read.
 *
 * Each line is written before the call returns, so an attempt killed mid-attack keeps every
 * finished call. Return values are never written, only their type.
 */

import { resolve } from "node:path";

import { appendLine, completeLines } from "./channel.js";
import { GazuaBlockedError } from "./errors.js";
import { asciiJson, dataEntries, type JsonValue, toJsonValue } from "./json.js";

export const RECORD_SCHEMA_VERSION = 1;
export const MAX_VALUE_CHARS = 4096;

/** Arguments as JSON data, each value cut to `MAX_VALUE_CHARS`, and whether any was cut. */
export function logArguments(argument: object | null, extra?: readonly unknown[]): [Record<string, JsonValue>, boolean] {
  const converted: Record<string, JsonValue> = {};
  let truncated = false;
  const entries: Array<[string, unknown, boolean]> =
    extra !== undefined ? [["$args", [...extra], true]] : argument === null ? [] : dataEntries(argument);
  for (const [name, value, isData] of entries) {
    let data: JsonValue = isData ? toJsonValue(value, MAX_VALUE_CHARS) : { $repr: "<accessor>" };
    if (typeof data === "string") {
      if (data.length > MAX_VALUE_CHARS) {
        data = data.slice(0, MAX_VALUE_CHARS);
        truncated = true;
      }
    } else {
      const text = asciiJson(data);
      if (text.length > MAX_VALUE_CHARS) {
        data = { $truncated: text.slice(0, MAX_VALUE_CHARS) };
        truncated = true;
      }
    }
    converted[name] = data;
  }
  return [converted, truncated];
}

export interface CallRecordFields {
  readonly tool: string;
  readonly arguments: Record<string, JsonValue>;
  readonly truncated: boolean;
  readonly actor: { readonly id: string | null; readonly source: "actor_arg" | "as_user" | "none" };
  readonly dry_run: boolean;
  readonly undeclared: boolean;
  readonly outcome: "returned" | "raised" | "blocked";
  readonly low_fidelity: boolean;
  readonly result_type: string | null;
  readonly error: { readonly type: string } | null;
  readonly block_reason: string | null;
  readonly injection: { readonly id: string; readonly delivered: boolean; readonly reason: string | null } | null;
}

export class CallLog {
  private nextSeq: number | null = null;

  constructor(readonly path: string) {}

  private firstSeq(): number {
    if (this.nextSeq === null) {
      this.nextSeq = completeLines(this.path) + 1;
    }
    return this.nextSeq;
  }

  /** Writes one record and returns its `seq`. A log that cannot be written blocks. */
  append(record: CallRecordFields): number {
    try {
      const seq = this.firstSeq();
      const line = asciiJson({ schema_version: RECORD_SCHEMA_VERSION, seq, ...record });
      appendLine(this.path, `${line}\n`);
      this.nextSeq = seq + 1;
      return seq;
    } catch {
      throw new GazuaBlockedError("call_log_unavailable");
    }
  }

  /** Fails closed before a tool runs when its call could not be recorded. */
  checkWritable(): void {
    try {
      this.firstSeq();
      appendLine(this.path, "");
    } catch {
      throw new GazuaBlockedError("call_log_unavailable");
    }
  }
}

const logs = new Map<string, CallLog>();

export function callLogFor(path: string): CallLog {
  const key = resolve(path);
  let log = logs.get(key);
  if (log === undefined) {
    log = new CallLog(key);
    logs.set(key, log);
  }
  return log;
}

export function clearCallLogs(): void {
  logs.clear();
}
