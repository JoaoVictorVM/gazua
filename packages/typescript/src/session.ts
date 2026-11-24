/**
 * The session a Gazua run hands to the tested process, read with the same rules as the Python
 * wrapper. A session that is referenced but cannot be read or validated blocks every tool:
 * running a tool for real is never the fallback. Nothing here reads `gazua.yaml`.
 */

import { closeSync, fstatSync, openSync, readSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, posix } from "node:path";

import type { JsonValue } from "./json.js";

export const SESSION_ENV = "GAZUA_SESSION";
export const MAX_SESSION_BYTES = 1024 * 1024;
const RECEIVER_HOST = "127.0.0.1";

export interface ToolPolicy {
  readonly dryRun: boolean;
  readonly actorArg: string | null;
  readonly hasDryRunReturn: boolean;
  readonly dryRunReturn: JsonValue;
}

export interface Actor {
  readonly id: string;
  readonly role: "attacker" | "victim";
}

export interface Injection {
  readonly id: string;
  readonly tool: string;
  readonly text: string;
  readonly maxDeliveries: number;
}

export interface ExecutionChannel {
  readonly executionId: string;
  readonly maxToolCalls: number;
  readonly eventsPath: string;
  readonly usageReporting: boolean;
}

export interface Session {
  readonly kind: "session";
  readonly runId: string;
  readonly mode: "tools" | "agent";
  readonly callLog: string;
  readonly actor: Actor | null;
  readonly asUser: string | null;
  readonly tools: ReadonlyMap<string, ToolPolicy>;
  readonly injections: readonly Injection[];
  readonly execution: ExecutionChannel | null;
}

/** A session that exists but cannot be trusted. `reason` is a short code. */
export interface InvalidSession {
  readonly kind: "invalid";
  readonly reason: string;
}

class SessionFormatError extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

const SESSION_KEYS = ["schema_version", "run_id", "mode", "call_log", "actor", "as_user", "tools", "injections"];
const EXECUTION_KEYS = ["execution_id", "max_tool_calls", "events_path", "receiver", "usage_reporting"];
const TOOL_KEYS = ["dry_run", "actor_arg", "has_dry_run_return", "dry_run_return"];
const ACTOR_KEYS = ["id", "role"];
const INJECTION_KEYS = ["id", "tool", "text", "max_deliveries"];
const RECEIVER_KEYS = ["host", "port", "token", "execution_id"];
const IDENTIFIER = /^[\p{L}_][\p{L}\p{N}_]*$/u;

function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SessionFormatError("session_invalid");
  }
  const found = Object.keys(value);
  if (found.length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) {
    throw new SessionFormatError("session_invalid");
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, empty = false): string {
  if (typeof value !== "string" || (!empty && value.length === 0)) {
    throw new SessionFormatError("session_invalid");
  }
  return value;
}

function optionalText(value: unknown): string | null {
  return value === null ? null : text(value);
}

function flag(value: unknown): boolean {
  if (typeof value !== "boolean") {
    throw new SessionFormatError("session_invalid");
  }
  return value;
}

function positive(value: unknown, maximum?: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (maximum !== undefined && (value as number) > maximum)) {
    throw new SessionFormatError("session_invalid");
  }
  return value as number;
}

function tool(value: unknown): ToolPolicy {
  const data = object(value, TOOL_KEYS);
  const actorArg = optionalText(data["actor_arg"]);
  if (actorArg !== null && !IDENTIFIER.test(actorArg)) {
    throw new SessionFormatError("session_invalid");
  }
  return {
    dryRun: flag(data["dry_run"]),
    actorArg,
    hasDryRunReturn: flag(data["has_dry_run_return"]),
    dryRunReturn: data["dry_run_return"] as JsonValue,
  };
}

function actor(value: unknown): Actor | null {
  if (value === null) {
    return null;
  }
  const data = object(value, ACTOR_KEYS);
  const role = data["role"];
  if (role !== "attacker" && role !== "victim") {
    throw new SessionFormatError("session_invalid");
  }
  return { id: text(data["id"]), role };
}

function injection(value: unknown): Injection {
  const data = object(value, INJECTION_KEYS);
  return {
    id: text(data["id"]),
    tool: text(data["tool"]),
    text: text(data["text"], true),
    maxDeliveries: positive(data["max_deliveries"]),
  };
}

/** A path inside the session's folder, written with forward slashes and no way out. */
function localFile(value: unknown, base: string): string {
  const relative = text(value);
  const parts = relative.split("/");
  if (relative.includes("\\") || relative.includes(":") || posix.isAbsolute(relative) || isAbsolute(relative) || parts.includes("..")) {
    throw new SessionFormatError("session_invalid");
  }
  return join(base, ...parts);
}

function receiver(value: unknown, executionId: string): void {
  if (value === null) {
    return;
  }
  const data = object(value, RECEIVER_KEYS);
  if (data["host"] !== RECEIVER_HOST || data["execution_id"] !== executionId) {
    throw new SessionFormatError("session_invalid");
  }
  positive(data["port"], 65535);
  text(data["token"]);
}

function execution(data: Record<string, unknown>, base: string): ExecutionChannel {
  const executionId = text(data["execution_id"]);
  const channel = {
    executionId,
    maxToolCalls: positive(data["max_tool_calls"]),
    eventsPath: localFile(data["events_path"], base),
    usageReporting: flag(data["usage_reporting"]),
  };
  receiver(data["receiver"], executionId);
  return channel;
}

/**
 * Validates session data. Version 1 and version 2 have distinct key sets, so one is never read
 * as the other, and an unknown version fails closed.
 */
export function parseSession(document: unknown, base: string): Session {
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    throw new SessionFormatError("session_invalid");
  }
  const version = (document as Record<string, unknown>)["schema_version"];
  if (version !== 1 && version !== 2) {
    throw new SessionFormatError("session_version");
  }
  const data = object(document, version === 1 ? SESSION_KEYS : [...SESSION_KEYS, ...EXECUTION_KEYS]);
  const mode = data["mode"];
  if (mode !== "tools" && mode !== "agent") {
    throw new SessionFormatError("session_invalid");
  }
  const tools = data["tools"];
  const injections = data["injections"];
  if (typeof tools !== "object" || tools === null || Array.isArray(tools) || !Array.isArray(injections)) {
    throw new SessionFormatError("session_invalid");
  }
  const policies = new Map<string, ToolPolicy>();
  for (const [name, policy] of Object.entries(tools as Record<string, unknown>)) {
    policies.set(text(name), tool(policy));
  }
  return {
    kind: "session",
    runId: text(data["run_id"]),
    mode,
    callLog: join(base, text(data["call_log"])),
    actor: actor(data["actor"]),
    asUser: optionalText(data["as_user"]),
    tools: policies,
    injections: injections.map(injection),
    execution: version === 2 ? execution(data, base) : null,
  };
}

function readSession(path: string): Session | InvalidSession {
  let descriptor: number;
  try {
    descriptor = openSync(path, "r");
  } catch {
    return { kind: "invalid", reason: "session_unreadable" };
  }
  let content: Buffer;
  try {
    const status = fstatSync(descriptor);
    if (!status.isFile()) {
      return { kind: "invalid", reason: "session_not_regular" };
    }
    if (status.size > MAX_SESSION_BYTES) {
      return { kind: "invalid", reason: "session_too_large" };
    }
    content = Buffer.alloc(MAX_SESSION_BYTES + 1);
    let length = 0;
    for (;;) {
      const read = readSync(descriptor, content, length, content.length - length, null);
      if (read === 0) {
        break;
      }
      length += read;
      if (length > MAX_SESSION_BYTES) {
        return { kind: "invalid", reason: "session_too_large" };
      }
    }
    content = content.subarray(0, length);
  } catch {
    return { kind: "invalid", reason: "session_unreadable" };
  } finally {
    closeSync(descriptor);
  }
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(content);
    return parseSession(JSON.parse(decoded), dirname(path));
  } catch (error) {
    if (error instanceof SessionFormatError) {
      return { kind: "invalid", reason: error.reason };
    }
    return { kind: "invalid", reason: "session_malformed" };
  }
}

const cache = new Map<string, Session | InvalidSession>();

/**
 * The session `GAZUA_SESSION` names. `null` means no Gazua run is in progress, so every tool is
 * a plain function call.
 */
export function sessionState(): Session | InvalidSession | null {
  const location = process.env[SESSION_ENV];
  if (location === undefined) {
    return null;
  }
  if (location.length === 0 || !isAbsolute(location)) {
    return { kind: "invalid", reason: "session_unreadable" };
  }
  let key: string;
  try {
    const status = statSync(location, { bigint: true });
    key = `${location}\u0000${status.mtimeNs}\u0000${status.size}\u0000${status.ino}`;
  } catch {
    return { kind: "invalid", reason: "session_unreadable" };
  }
  const cached = cache.get(key);
  if (cached !== undefined) {
    return cached;
  }
  const state = readSession(location);
  cache.set(key, state);
  return state;
}

export interface Decision {
  readonly dryRun: boolean;
  readonly policy: ToolPolicy | null;
  readonly undeclared: boolean;
  readonly lowFidelity: boolean;
}

/** What one call to a tool does. A tool the session does not name always runs in dry-run. */
export function decide(session: Session, name: string): Decision {
  const policy = session.tools.get(name) ?? null;
  const dryRun = policy === null ? true : policy.dryRun;
  return {
    dryRun,
    policy,
    undeclared: policy === null,
    lowFidelity: dryRun && (policy === null || !policy.hasDryRunReturn),
  };
}

export function clearSessionCache(): void {
  cache.clear();
}
