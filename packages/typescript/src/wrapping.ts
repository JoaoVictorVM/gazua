/**
 * `wrap` and `tool`: the two ways a TypeScript target hands its tools to Gazua.
 *
 * Outside a Gazua run both return what they received, so a test entrypoint costs nothing in
 * production. Inside a run every call reserves a slot under the ceiling, decides between the
 * real function and its dry-run value, imposes the attacker's identity, applies the armed
 * injection and records the call. A tool in dry-run never reaches the original function.
 */

import { types } from "node:util";

import { callLogFor, type CallLog, type CallRecordFields, logArguments } from "./call-log.js";
import { GazuaBlockedError, UnsupportedToolError } from "./errors.js";
import { inject } from "./injection.js";
import { dataEntries, isPlainObject, type JsonValue, safeErrorType } from "./json.js";
import { recordReturn } from "./observations.js";
import { admit, currentIdentityHook } from "./policy.js";
import { cachedProxy, register, type ToolFunction } from "./registry.js";
import { type Decision, decide, type Session, sessionState } from "./session.js";

export const GENERIC_DRY_RUN_RETURN = "ok";
const PROXY = Symbol.for("gazua.tool");
const ASYNC_FUNCTION = Object.getPrototypeOf(async function () {}) as object;
const GENERATOR_FUNCTION = Object.getPrototypeOf(function* () {}) as object;
const ASYNC_GENERATOR_FUNCTION = Object.getPrototypeOf(async function* () {}) as object;

function resultType(value: unknown): string {
  if (value === null) {
    return "null";
  }
  return Array.isArray(value) ? "array" : typeof value;
}

/** A copy of `value` with `field` set, built from descriptors so no getter of the agent runs. */
function withField(value: object, field: string, content: string): object {
  const copy = Object.create(Object.getPrototypeOf(value) as object | null, Object.getOwnPropertyDescriptors(value)) as object;
  Object.defineProperty(copy, field, { value: content, writable: true, enumerable: true, configurable: true });
  return copy;
}

class Call {
  actorId: string | null = null;
  actorSource: "actor_arg" | "as_user" | "none" = "none";

  constructor(
    readonly name: string,
    readonly session: Session,
    readonly log: CallLog,
    readonly decision: Decision,
    public argument: object | null,
    readonly extra?: readonly unknown[],
  ) {}

  finish(outcome: CallRecordFields["outcome"], fields: Partial<CallRecordFields> = {}): number {
    const [logged, truncated] = logArguments(this.argument, this.extra);
    return this.log.append({
      tool: this.name,
      arguments: logged,
      truncated,
      actor: { id: this.actorId, source: this.actorSource },
      dry_run: this.decision.dryRun,
      undeclared: this.decision.undeclared,
      outcome,
      low_fidelity: this.decision.lowFidelity,
      result_type: null,
      error: null,
      block_reason: null,
      injection: null,
      ...fields,
    });
  }

  block(reason: string): GazuaBlockedError {
    this.finish("blocked", { block_reason: reason });
    return new GazuaBlockedError(reason);
  }

  dryRunValue(): unknown {
    const policy = this.decision.policy;
    if (policy !== null && policy.hasDryRunReturn) {
      return structuredClone(policy.dryRunReturn as JsonValue);
    }
    return GENERIC_DRY_RUN_RETURN;
  }

  returned(value: unknown): unknown {
    const [delivered, injection] = inject(this.session, this.name, value);
    const seq = this.finish("returned", { result_type: resultType(value), injection });
    recordReturn(this.session, seq, value, delivered);
    return delivered;
  }

  raised(error: unknown): void {
    this.finish("raised", { error: { type: safeErrorType(error) } });
  }
}

function start(name: string, args: readonly unknown[]): Call | null {
  const state = sessionState();
  if (state === null) {
    return null;
  }
  if (state.kind === "invalid") {
    throw new GazuaBlockedError("invalid_session", state.reason);
  }
  admit(state);
  const log = callLogFor(state.callLog);
  log.checkWritable();
  const decision = decide(state, name);
  const given = args.length === 1 && args[0] === undefined ? [] : args;
  if (given.length > 1 || (given.length === 1 && !isPlainObject(given[0]))) {
    throw new Call(name, state, log, decision, null, given).block("tool_arguments_unsupported");
  }
  const call = new Call(name, state, log, decision, given.length === 1 ? (given[0] as object) : null);
  const actor = state.actor;
  if (actor === null) {
    return call;
  }
  const actorArg = decision.policy?.actorArg ?? null;
  if (actorArg !== null) {
    call.actorId = actor.id;
    call.actorSource = "actor_arg";
    if (call.argument === null) {
      throw call.block("actor_arg_not_accepted");
    }
    call.argument = withField(call.argument, actorArg, actor.id);
  } else if (state.asUser !== null) {
    call.actorId = actor.id;
    call.actorSource = "as_user";
  }
  return call;
}

/** Runs the tool and records its outcome; a native promise is followed to its end. */
function complete(call: Call, run: () => unknown): unknown {
  let value: unknown;
  try {
    value = run();
  } catch (error) {
    call.raised(error);
    throw error;
  }
  if (types.isPromise(value)) {
    return value.then(
      (resolved) => call.returned(resolved),
      (error: unknown) => {
        call.raised(error);
        throw error;
      },
    );
  }
  return call.returned(value);
}

/** Runs the tool inside the target's identity hook. A hook that never runs it blocks the call. */
function asUser(call: Call, run: () => unknown): unknown {
  const hook = currentIdentityHook();
  if (hook === null || call.actorId === null) {
    throw call.block("identity_hook");
  }
  let entered = false;
  const invoke = (): unknown => {
    if (entered) {
      throw new GazuaBlockedError("identity_hook");
    }
    entered = true;
    return complete(call, run);
  };
  let result: unknown;
  try {
    result = hook(call.actorId, invoke);
  } catch (error) {
    if (!entered) {
      throw call.block("identity_hook");
    }
    throw error;
  }
  if (types.isPromise(result)) {
    return result.then(
      (value) => {
        if (!entered) {
          throw call.block("identity_hook");
        }
        return value;
      },
      (error: unknown) => {
        if (!entered) {
          throw call.block("identity_hook");
        }
        throw error;
      },
    );
  }
  if (!entered) {
    throw call.block("identity_hook");
  }
  return result;
}

function makeProxy(name: string, original: ToolFunction, isAsync: boolean): ToolFunction {
  function proxy(this: unknown, ...args: unknown[]): unknown {
    try {
      const call = start(name, args);
      if (call === null) {
        return Reflect.apply(original, this, args);
      }
      if (call.decision.dryRun) {
        const value = call.returned(call.dryRunValue());
        return isAsync ? Promise.resolve(value) : value;
      }
      const target = this;
      const run = (): unknown => Reflect.apply(original, target, call.argument === null ? [] : [call.argument]);
      return call.actorSource === "as_user" ? asUser(call, run) : complete(call, run);
    } catch (error) {
      if (isAsync) {
        return Promise.reject(error as Error);
      }
      throw error;
    }
  }
  const length = Reflect.getOwnPropertyDescriptor(original, "length");
  Object.defineProperty(proxy, "name", { value: name, configurable: true });
  Object.defineProperty(proxy, "length", { value: length !== undefined && "value" in length ? length.value : 0, configurable: true });
  Object.defineProperty(proxy, PROXY, { value: name });
  return proxy as unknown as ToolFunction;
}

function isProxy(value: unknown): boolean {
  return typeof value === "function" && Reflect.getOwnPropertyDescriptor(value, PROXY) !== undefined;
}

function ownData(value: object, key: string): unknown {
  const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
  return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
}

function wrapFunction(item: unknown, explicit: string | undefined): ToolFunction {
  if (typeof item !== "function") {
    throw new UnsupportedToolError("A tool must be a function, not a plain value.");
  }
  if (isProxy(item)) {
    return item as ToolFunction;
  }
  if (Function.prototype.toString.call(item).startsWith("class")) {
    throw new UnsupportedToolError("A tool must be a function, not a class.");
  }
  const kind = Object.getPrototypeOf(item) as object;
  if (kind === GENERATOR_FUNCTION || kind === ASYNC_GENERATOR_FUNCTION) {
    throw new UnsupportedToolError("Generator functions cannot be wrapped as tools.");
  }
  const name = explicit ?? ownData(item, "name");
  if (typeof name !== "string" || name.length === 0) {
    throw new UnsupportedToolError("A tool needs a name; pass it in a record or with tool({ name }).");
  }
  const length = ownData(item, "length");
  if (typeof length === "number" && length > 1) {
    throw new UnsupportedToolError("During a Gazua run a tool takes no argument or one object of named arguments.");
  }
  const original = item as ToolFunction;
  const cached = cachedProxy(name, original);
  if (cached !== undefined) {
    return cached;
  }
  const isAsync = kind === ASYNC_FUNCTION;
  const proxy = makeProxy(name, original, isAsync);
  register({ name, original, proxy, isAsync, argumentStyle: length === 0 ? "none" : "object" });
  return proxy;
}

function isToolObject(item: unknown): item is object {
  return (
    typeof item === "object" &&
    item !== null &&
    !types.isProxy(item) &&
    typeof ownData(item, "name") === "string" &&
    typeof ownData(item, "func") === "function"
  );
}

/** A shallow copy of a tool object with its function replaced by a proxy. */
function wrapObject(item: object): object {
  const name = ownData(item, "name") as string;
  const copy = Object.create(Object.getPrototypeOf(item) as object | null, Object.getOwnPropertyDescriptors(item)) as object;
  Object.defineProperty(copy, "func", {
    value: wrapFunction(ownData(item, "func"), name),
    writable: true,
    enumerable: true,
    configurable: true,
  });
  return copy;
}

function wrapItem(item: unknown, name: string | undefined): unknown {
  if (typeof item !== "function" && isToolObject(item)) {
    return wrapObject(item);
  }
  return wrapFunction(item, name);
}

/**
 * Returns the same tools as proxies for a Gazua run, or the very same value outside of one.
 *
 * Accepts a record from tool name to function, an array or tuple of named functions, and tool
 * objects with `name` and `func`. The container keeps its shape and order; tool objects are
 * copied, never changed in place.
 */
export function wrap<T>(tools: T): T {
  if (sessionState() === null) {
    return tools;
  }
  if (Array.isArray(tools)) {
    return tools.map((item: unknown) => wrapItem(item, undefined)) as T;
  }
  if (isPlainObject(tools)) {
    const copy = Object.create(Object.getPrototypeOf(tools) as object | null) as Record<string, unknown>;
    for (const [key, value, isData] of dataEntries(tools)) {
      if (!isData) {
        throw new UnsupportedToolError("Tools in a record must be plain values, not accessors.");
      }
      copy[key] = wrapItem(value, key);
    }
    return copy as T;
  }
  throw new UnsupportedToolError("wrap expects an array or a record of tools.");
}

export interface ToolOptions {
  readonly name: string;
}

/**
 * Marks a function as a tool. Outside a Gazua run it returns the function itself.
 *
 * `tool(fn)` takes the function's own name; `tool({ name })(fn)` names it explicitly.
 */
export function tool<F extends ToolFunction>(function_: F): F;
export function tool(options: ToolOptions): <F extends ToolFunction>(function_: F) => F;
export function tool<F extends ToolFunction>(argument: F | ToolOptions): F | (<G extends ToolFunction>(function_: G) => G) {
  if (typeof argument === "function") {
    const function_ = argument as F;
    return sessionState() === null ? function_ : (wrapFunction(function_, undefined) as F);
  }
  const name = (argument as Partial<ToolOptions> | null)?.name;
  if (typeof name !== "string" || name.length === 0) {
    throw new UnsupportedToolError("tool({ name }) needs a non-empty name.");
  }
  return <G extends ToolFunction>(function_: G): G =>
    sessionState() === null ? function_ : (wrapFunction(function_, name) as G);
}
