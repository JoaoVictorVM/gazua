/**
 * The tested project's compiled module and its exports, checked before and after import.
 *
 * The module is a relative path inside the project, a regular `.js` or `.mjs` file reached
 * without links. It is imported only after the session and the first message are valid.
 */

import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

import { safeErrorType } from "./json.js";
import type { Exports } from "./protocol.js";

export type Entrypoint = (message: string) => string | Promise<string>;
export type ResetHook = () => void | Promise<void>;
export type OutputSink = (output: unknown) => unknown;

export interface TargetHooks {
  readonly entrypoint: Entrypoint;
  readonly reset: ResetHook | null;
  readonly asUser: ((actorId: string, invoke: () => unknown) => unknown) | null;
  readonly outputSink: OutputSink | null;
}

/** The module or an export cannot be used. `reason` is a short code. */
export class TargetError extends Error {
  constructor(
    readonly reason: string,
    readonly errorType: string | null = null,
  ) {
    super(reason);
  }
}

const EXTENSIONS = [".js", ".mjs"];

/** The absolute path of `module` inside `root`, refusing anything that could leave it. */
export function checkModulePath(root: string, module: string): string {
  if (
    module.includes("\\") ||
    module.includes(":") ||
    module.includes("?") ||
    module.includes("#") ||
    module.includes("\u0000") ||
    isAbsolute(module) ||
    module.split("/").some((part) => part === ".." || part === "") ||
    !EXTENSIONS.some((extension) => module.endsWith(extension))
  ) {
    throw new TargetError("module_path_invalid");
  }
  const base = realpathSync(root);
  let current = base;
  for (const part of module.split("/")) {
    if (part === ".") {
      continue;
    }
    current = join(current, part);
    let status;
    try {
      status = lstatSync(current);
    } catch {
      throw new TargetError("module_not_found");
    }
    if (status.isSymbolicLink()) {
      throw new TargetError("module_path_invalid");
    }
  }
  const status = lstatSync(current);
  const inside = relative(base, resolve(current));
  if (!status.isFile() || inside.startsWith(`..${sep}`) || inside === ".." || isAbsolute(inside)) {
    throw new TargetError("module_path_invalid");
  }
  return current;
}

function exported(namespace: Record<string, unknown>, name: string | null, required: boolean): ((...args: never[]) => unknown) | null {
  if (name === null) {
    return null;
  }
  const descriptor = Reflect.getOwnPropertyDescriptor(namespace, name);
  if (descriptor === undefined) {
    throw new TargetError(required ? "entrypoint_export_missing" : "hook_export_missing");
  }
  const value: unknown = descriptor.value;
  if (typeof value !== "function") {
    throw new TargetError("export_not_callable");
  }
  return value as (...args: never[]) => unknown;
}

/** Imports the module and returns its declared exports, all checked to be functions. */
export async function loadTarget(path: string, exports: Exports): Promise<TargetHooks> {
  let namespace: Record<string, unknown>;
  try {
    namespace = (await import(pathToFileURL(path).href)) as Record<string, unknown>;
  } catch (error) {
    throw new TargetError("module_import_failed", safeErrorType(error));
  }
  return {
    entrypoint: exported(namespace, exports.entrypoint, true) as Entrypoint,
    reset: exported(namespace, exports.reset, false) as ResetHook | null,
    asUser: exported(namespace, exports.as_user, false) as TargetHooks["asUser"],
    outputSink: exported(namespace, exports.output_sink, false) as OutputSink | null,
  };
}
