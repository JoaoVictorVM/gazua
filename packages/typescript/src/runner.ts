/**
 * The runner the Gazua Python worker starts for one attempt. Reserved to Gazua's launcher; a
 * target never imports it.
 *
 * Stdout carries only protocol lines: the target's console and `process.stdout.write` go to
 * stderr, which the worker drains and discards. The session and the first message are checked
 * before the target's module is imported, and only `describe`, `invoke`, `reset`, `sink` and
 * `close` exist. A protocol violation ends the runner without another line.
 */

import { readFileSync } from "node:fs";

import { GazuaBlockedError } from "./errors.js";
import { arm, disarm } from "./injection.js";
import { isPlainObject, type JsonValue, nativeJson, safeErrorType } from "./json.js";
import { type AsUserHook, setIdentityHook } from "./policy.js";
import {
  encode,
  MAX_LINE_BYTES,
  parseLine,
  ProtocolError,
  type ToolDescription,
  type ToPython,
  type ToRunner,
  validate,
} from "./protocol.js";
import { snapshot } from "./registry.js";
import { type Session, sessionState } from "./session.js";
import { checkModulePath, loadTarget, TargetError, type TargetHooks } from "./target.js";
import { channelFor } from "./channel.js";
import { GazuaAuthenticationError, GazuaRateLimited } from "./telemetry.js";

export const EXIT_PROTOCOL = 65;
export const EXIT_INTERNAL = 70;

type Writer = (line: string, done?: () => void) => void;

/** The version of this package, read from its manifest next to the compiled files. */
function sdkVersion(): string {
  for (const candidate of ["../package.json", "../../package.json"]) {
    try {
      const manifest = JSON.parse(readFileSync(new URL(candidate, import.meta.url), "utf-8")) as { name?: unknown; version?: unknown };
      if (manifest.name === "gazua" && typeof manifest.version === "string") {
        return manifest.version;
      }
    } catch {
      // The next candidate covers the layout of the package's own test build.
    }
  }
  return "0.0.0";
}

/** The registered tools, one entry per name; distinct functions under a name are ambiguous. */
export function describeTools(): ToolDescription[] {
  return [...snapshot()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([name, entries]) => ({
      name,
      supports_sync: entries.some((entry) => !entry.isAsync),
      supports_async: entries.some((entry) => entry.isAsync),
      argument_style: entries[0]?.argumentStyle ?? "none",
      ambiguous: entries.length > 1,
    }));
}

function failure(request: string, code: string, errorType: string | null = null, retryAfter: number | null = null): ToPython {
  return { type: "error", request_id: request, code, error_type: errorType, retry_after: retryAfter };
}

/** The checked result of the output sink: exactly a boolean effect and a non-empty JSON proof. */
function sinkResult(request: string, value: unknown): ToPython {
  if (!isPlainObject(value)) {
    return failure(request, "sink_result_invalid");
  }
  const keys = Object.keys(value);
  const effect = Reflect.getOwnPropertyDescriptor(value, "effect");
  const proof = Reflect.getOwnPropertyDescriptor(value, "proof");
  if (keys.length !== 2 || effect === undefined || proof === undefined || !("value" in effect) || !("value" in proof)) {
    return failure(request, "sink_result_invalid");
  }
  if (typeof effect.value !== "boolean" || !isPlainObject(proof.value)) {
    return failure(request, "sink_result_invalid");
  }
  let clean: JsonValue;
  try {
    clean = nativeJson(proof.value);
  } catch {
    return failure(request, "sink_result_invalid");
  }
  if (clean === null || typeof clean !== "object" || Array.isArray(clean) || Object.keys(clean).length === 0) {
    return failure(request, "sink_result_invalid");
  }
  return { type: "sink_result", request_id: request, effect: effect.value, proof: clean };
}

export class Runner {
  private opened = false;
  private closed = false;
  private last = 0;
  private hooks: TargetHooks | null = null;
  private session: Session | null = null;

  constructor(
    private readonly write: Writer,
    private readonly exit: (code: number) => void,
    private readonly root: string,
  ) {}

  private send(message: ToPython, then?: () => void): void {
    this.write(encode(message), then);
  }

  private stop(code: number, message?: ToPython): void {
    this.closed = true;
    if (message === undefined) {
      this.exit(code);
    } else {
      this.send(message, () => this.exit(code));
    }
  }

  /** Handles one line, without its newline. */
  async handle(line: Uint8Array): Promise<void> {
    if (this.closed) {
      return;
    }
    let message: ToRunner;
    try {
      message = validate("to_runner", parseLine(line));
    } catch (error) {
      if (error instanceof ProtocolError) {
        this.stop(EXIT_PROTOCOL);
        return;
      }
      throw error;
    }
    const id = Number(message.request_id);
    if (id <= this.last || this.opened === (message.type === "open")) {
      this.stop(EXIT_PROTOCOL);
      return;
    }
    this.last = id;
    switch (message.type) {
      case "open":
        await this.open(message);
        return;
      case "invoke":
        this.send(await this.invoke(message.request_id, message.message, message.armed_injection_id));
        return;
      case "reset":
        this.send(await this.reset(message.request_id));
        return;
      case "sink":
        this.send(await this.sink(message.request_id, message.value));
        return;
      case "close":
        this.stop(0, { type: "closed", request_id: message.request_id });
        return;
    }
  }

  private async open(message: Extract<ToRunner, { type: "open" }>): Promise<void> {
    this.opened = true;
    const request = message.request_id;
    const state = sessionState();
    if (state === null || state.kind === "invalid") {
      this.stop(0, failure(request, "session_invalid"));
      return;
    }
    this.session = state;
    try {
      const path = checkModulePath(this.root, message.module);
      this.hooks = await loadTarget(path, message.exports);
    } catch (error) {
      if (error instanceof TargetError) {
        this.stop(0, failure(request, error.reason, error.errorType));
        return;
      }
      throw error;
    }
    const asUser = this.hooks.asUser;
    setIdentityHook(asUser === null ? null : (asUser as AsUserHook));
    const ready: ToPython = {
      type: "ready",
      request_id: request,
      sdk_version: sdkVersion(),
      node_version: process.versions.node,
      tools: describeTools(),
    };
    if (message.operation === "describe") {
      this.stop(0, ready);
    } else {
      this.send(ready);
    }
  }

  private async invoke(request: string, text: string, armed: string | null): Promise<ToPython> {
    const hooks = this.hooks as TargetHooks;
    const session = this.session as Session;
    if (armed !== null && !session.injections.some((item) => item.id === armed)) {
      return failure(request, "injection_unknown");
    }
    arm(armed);
    let response: unknown;
    try {
      response = await hooks.entrypoint(text);
    } catch (error) {
      if (error instanceof GazuaRateLimited) {
        return failure(request, "rate_limited", "GazuaRateLimited", error.retryAfter);
      }
      if (error instanceof GazuaAuthenticationError) {
        return failure(request, "agent_authentication_failed", "GazuaAuthenticationError");
      }
      if (error instanceof GazuaBlockedError) {
        return failure(request, "blocked", "GazuaBlockedError");
      }
      return failure(request, "entrypoint_error", safeErrorType(error));
    } finally {
      disarm();
    }
    if (typeof response !== "string") {
      return failure(request, "response_not_text", "ResponseNotText");
    }
    return { type: "result", request_id: request, response };
  }

  private emit(kind: string, payload: Record<string, JsonValue>): void {
    const execution = this.session?.execution ?? null;
    if (execution !== null) {
      channelFor(execution).emit(kind, payload, true);
    }
  }

  private async reset(request: string): Promise<ToPython> {
    const reset = this.hooks?.reset ?? null;
    if (reset === null) {
      return failure(request, "hook_missing");
    }
    try {
      this.emit("reset_started", {});
    } catch {
      return failure(request, "execution_channel_unavailable");
    }
    let outcome: ToPython;
    try {
      await reset();
      outcome = { type: "reset_done", request_id: request };
    } catch (error) {
      outcome = failure(request, "reset_error", safeErrorType(error));
    }
    try {
      this.emit("reset_before", { outcome: outcome.type === "reset_done" ? "succeeded" : "failed" });
    } catch {
      return failure(request, "execution_channel_unavailable");
    }
    return outcome;
  }

  private async sink(request: string, value: JsonValue): Promise<ToPython> {
    const sink = this.hooks?.outputSink ?? null;
    if (sink === null) {
      return failure(request, "hook_missing");
    }
    let result: unknown;
    try {
      result = await sink(value);
    } catch (error) {
      return failure(request, "sink_error", safeErrorType(error));
    }
    return sinkResult(request, result);
  }
}

/** Splits a byte stream into lines, refusing any line longer than the protocol allows. */
export class LineReader {
  private buffer: Buffer = Buffer.alloc(0);

  constructor(
    private readonly onLine: (line: Uint8Array) => void,
    private readonly onTooLong: () => void,
  ) {}

  push(chunk: Buffer): void {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    for (;;) {
      const end = this.buffer.indexOf(0x0a);
      if (end < 0) {
        if (this.buffer.length > MAX_LINE_BYTES) {
          this.onTooLong();
        }
        return;
      }
      const line = this.buffer.subarray(0, end);
      this.buffer = this.buffer.subarray(end + 1);
      if (line.length > MAX_LINE_BYTES) {
        this.onTooLong();
        return;
      }
      this.onLine(line);
    }
  }
}

/** Starts the runner on this process's stdin and stdout. Called by Gazua's launcher only. */
export function main(): void {
  const stdout = process.stdout;
  const original = stdout.write.bind(stdout) as (chunk: string, callback?: () => void) => boolean;
  const toStderr = process.stderr.write.bind(process.stderr);
  // The target's console and direct writes would break the framing; they go to stderr.
  stdout.write = toStderr as typeof stdout.write;
  const write: Writer = (line, done) => {
    original(line, done);
  };
  const exit = (code: number): void => {
    process.exit(code);
  };
  process.on("uncaughtException", () => exit(EXIT_INTERNAL));
  process.on("unhandledRejection", () => exit(EXIT_INTERNAL));
  const runner = new Runner(write, exit, process.cwd());
  let queue = Promise.resolve();
  const reader = new LineReader(
    (line) => {
      const copy = Uint8Array.from(line);
      queue = queue.then(() => runner.handle(copy)).catch(() => exit(EXIT_INTERNAL));
    },
    () => exit(EXIT_PROTOCOL),
  );
  process.stdin.on("data", (chunk: Buffer) => reader.push(chunk));
  process.stdin.on("end", () => {
    void queue.finally(() => exit(0));
  });
}
