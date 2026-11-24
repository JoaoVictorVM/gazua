/**
 * Local JSON Lines protocol, version 1, between the Python worker and this package's runner.
 *
 * Every line is one UTF-8 JSON object of at most 1 MiB and 32 levels, with the exact keys of
 * its type. Errors carry codes and class names only: never a message, a stack, a path, an
 * argument, a tool result or a provider object.
 */

import { type JsonValue, withinDepth } from "./json.js";

export const PROTOCOL_VERSION = 1;
export const MAX_LINE_BYTES = 1024 * 1024;
export const MAX_DEPTH = 32;
export const MAX_RETRY_AFTER = 3600;
const REQUEST_ID = /^[1-9][0-9]{0,15}$/;
const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const ERROR_TYPE = /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/;
const EXPORT_NAME = /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/;
const VERSION = /^[0-9A-Za-z.+-]{1,64}$/;

export type Direction = "to_runner" | "to_python";

export interface Exports {
  readonly entrypoint: string;
  readonly reset: string | null;
  readonly as_user: string | null;
  readonly output_sink: string | null;
}

export type ToRunner =
  | {
      readonly type: "open";
      readonly request_id: string;
      readonly operation: "run" | "describe";
      readonly module: string;
      readonly exports: Exports;
    }
  | { readonly type: "invoke"; readonly request_id: string; readonly message: string; readonly armed_injection_id: string | null }
  | { readonly type: "reset"; readonly request_id: string }
  | { readonly type: "sink"; readonly request_id: string; readonly value: JsonValue }
  | { readonly type: "close"; readonly request_id: string };

export interface ToolDescription {
  readonly name: string;
  readonly supports_sync: boolean;
  readonly supports_async: boolean;
  readonly argument_style: "none" | "object";
  readonly ambiguous: boolean;
}

export type ToPython =
  | {
      readonly type: "ready";
      readonly request_id: string;
      readonly sdk_version: string;
      readonly node_version: string;
      readonly tools: readonly ToolDescription[];
    }
  | { readonly type: "result"; readonly request_id: string; readonly response: string }
  | { readonly type: "reset_done"; readonly request_id: string }
  | { readonly type: "sink_result"; readonly request_id: string; readonly effect: boolean; readonly proof: { readonly [key: string]: JsonValue } }
  | { readonly type: "closed"; readonly request_id: string }
  | {
      readonly type: "error";
      readonly request_id: string;
      readonly code: string;
      readonly error_type: string | null;
      readonly retry_after: number | null;
    };

/** A line that breaks the protocol. `reason` is a short code; the line itself is never kept. */
export class ProtocolError extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

const KEYS: Record<Direction, Record<string, readonly string[]>> = {
  to_runner: {
    open: ["operation", "module", "exports"],
    invoke: ["message", "armed_injection_id"],
    reset: [],
    sink: ["value"],
    close: [],
  },
  to_python: {
    ready: ["sdk_version", "node_version", "tools"],
    result: ["response"],
    reset_done: [],
    sink_result: ["effect", "proof"],
    closed: [],
    error: ["code", "error_type", "retry_after"],
  },
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: Record<string, unknown>, keys: readonly string[]): void {
  const found = Object.keys(value);
  if (found.length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) {
    throw new ProtocolError("protocol_fields");
  }
}

function check(condition: boolean, reason = "protocol_fields"): void {
  if (!condition) {
    throw new ProtocolError(reason);
  }
}

function optional(value: unknown, pattern: RegExp): boolean {
  return value === null || (typeof value === "string" && pattern.test(value));
}

/** Decodes and parses one line, without its newline, into a JSON object. */
export function parseLine(line: Uint8Array): Record<string, unknown> {
  if (line.byteLength > MAX_LINE_BYTES) {
    throw new ProtocolError("protocol_line_too_long");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(line);
  } catch {
    throw new ProtocolError("protocol_encoding");
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ProtocolError("protocol_json");
  }
  if (!isObject(value)) {
    throw new ProtocolError("protocol_json");
  }
  if (!withinDepth(value, MAX_DEPTH)) {
    throw new ProtocolError("protocol_depth");
  }
  return value;
}

/** Checks a parsed message of `direction` and returns it typed. */
export function validate(direction: "to_runner", value: Record<string, unknown>): ToRunner;
export function validate(direction: "to_python", value: Record<string, unknown>): ToPython;
export function validate(direction: Direction, value: Record<string, unknown>): ToRunner | ToPython {
  check(value["protocol_version"] === PROTOCOL_VERSION, "protocol_version");
  const type = value["type"];
  const extra = typeof type === "string" ? KEYS[direction][type] : undefined;
  check(extra !== undefined, "protocol_type");
  exact(value, ["protocol_version", "type", "request_id", ...(extra ?? [])]);
  check(typeof value["request_id"] === "string" && REQUEST_ID.test(value["request_id"]));
  switch (type) {
    case "open": {
      check(value["operation"] === "run" || value["operation"] === "describe");
      check(typeof value["module"] === "string" && value["module"].length > 0 && value["module"].length <= 4096);
      const exports = value["exports"];
      check(isObject(exports));
      const declared = exports as Record<string, unknown>;
      exact(declared, ["entrypoint", "reset", "as_user", "output_sink"]);
      check(typeof declared["entrypoint"] === "string" && EXPORT_NAME.test(declared["entrypoint"]));
      check(["reset", "as_user", "output_sink"].every((key) => optional(declared[key], EXPORT_NAME)));
      break;
    }
    case "invoke":
      check(typeof value["message"] === "string");
      check(optional(value["armed_injection_id"], /^.{1,512}$/su));
      break;
    case "ready": {
      check(optional(value["sdk_version"], VERSION) && value["sdk_version"] !== null);
      check(optional(value["node_version"], VERSION) && value["node_version"] !== null);
      const tools = value["tools"];
      check(Array.isArray(tools) && tools.length <= 1024);
      const names = new Set<string>();
      for (const item of tools as unknown[]) {
        check(isObject(item));
        const tool = item as Record<string, unknown>;
        exact(tool, ["name", "supports_sync", "supports_async", "argument_style", "ambiguous"]);
        check(typeof tool["name"] === "string" && tool["name"].length > 0 && tool["name"].length <= 256);
        check(!names.has(tool["name"] as string), "protocol_duplicate_tool");
        names.add(tool["name"] as string);
        check(typeof tool["supports_sync"] === "boolean" && typeof tool["supports_async"] === "boolean");
        check(tool["argument_style"] === "none" || tool["argument_style"] === "object");
        check(typeof tool["ambiguous"] === "boolean");
      }
      break;
    }
    case "result":
      check(typeof value["response"] === "string");
      break;
    case "sink_result":
      check(typeof value["effect"] === "boolean");
      check(isObject(value["proof"]) && Object.keys(value["proof"] as object).length > 0);
      break;
    case "error": {
      check(typeof value["code"] === "string" && CODE.test(value["code"]));
      check(optional(value["error_type"], ERROR_TYPE));
      const retry = value["retry_after"];
      check(retry === null || (typeof retry === "number" && Number.isFinite(retry) && retry >= 0 && retry <= MAX_RETRY_AFTER));
      break;
    }
    default:
      break;
  }
  return value as unknown as ToRunner | ToPython;
}

/** One line of the runner's output, newline included. */
export function encode(message: ToPython): string {
  const line = JSON.stringify({ protocol_version: PROTOCOL_VERSION, ...message });
  if (Buffer.byteLength(line, "utf-8") > MAX_LINE_BYTES) {
    throw new ProtocolError("protocol_line_too_long");
  }
  return `${line}\n`;
}
