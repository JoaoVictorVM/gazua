/**
 * JSON data built from the target's values without running any of the target's code.
 *
 * `JSON.stringify` calls `toJSON`, getters and proxy traps, so values of the target are walked
 * here through property descriptors instead, and only plain objects and arrays are entered.
 */

import { types } from "node:util";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export const MAX_DEPTH = 32;

/** The value is not plain JSON data. */
export class Opaque extends Error {}

/** A plain object: created by a literal or with a null prototype, never a proxy. */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || types.isProxy(value) || Array.isArray(value)) {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isPlainArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && !types.isProxy(value) && Object.getPrototypeOf(value) === Array.prototype;
}

/** Own enumerable string keys with their data values; an accessor yields `undefined`. */
export function dataEntries(value: object): Array<[string, unknown, boolean]> {
  const entries: Array<[string, unknown, boolean]> = [];
  for (const key of Object.keys(value)) {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) {
      continue;
    }
    const isData = "value" in descriptor;
    entries.push([key, isData ? descriptor.value : undefined, isData]);
  }
  return entries;
}

/** `value` when it is made only of plain JSON types; otherwise throws `Opaque`. */
export function nativeJson(value: unknown, depth = 0): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Opaque();
    }
    return value;
  }
  if (depth >= MAX_DEPTH) {
    throw new Opaque();
  }
  if (isPlainArray(value)) {
    const items: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor)) {
        throw new Opaque();
      }
      items.push(nativeJson(descriptor.value, depth + 1));
    }
    return items;
  }
  if (isPlainObject(value)) {
    const result: { [key: string]: JsonValue } = {};
    for (const [key, item, isData] of dataEntries(value)) {
      if (!isData) {
        throw new Opaque();
      }
      result[key] = nativeJson(item, depth + 1);
    }
    return result;
  }
  throw new Opaque();
}

/** A short description of a value that is not JSON data, without calling into it. */
export function describe(value: unknown, limit: number): string {
  let text: string;
  switch (typeof value) {
    case "undefined":
      text = "undefined";
      break;
    case "number":
      text = String(value);
      break;
    case "bigint":
      text = `${String(value)}n`;
      break;
    case "symbol":
      text = "<symbol>";
      break;
    case "function":
      text = "<function>";
      break;
    default:
      text = types.isProxy(value) ? "<proxy>" : "<object>";
  }
  return text.slice(0, limit);
}

/** JSON data for any value. What JSON cannot hold becomes `{"$repr": ...}`. */
export function toJsonValue(value: unknown, limit: number, depth = 0): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : { $repr: describe(value, limit) };
  }
  if (depth >= MAX_DEPTH) {
    return { $repr: describe(value, limit) };
  }
  if (isPlainArray(value)) {
    const items: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, String(index));
      items.push(
        descriptor !== undefined && "value" in descriptor
          ? toJsonValue(descriptor.value, limit, depth + 1)
          : { $repr: "<accessor>" },
      );
    }
    return items;
  }
  if (isPlainObject(value)) {
    const result: { [key: string]: JsonValue } = {};
    for (const [key, item, isData] of dataEntries(value)) {
      result[key] = isData ? toJsonValue(item, limit, depth + 1) : { $repr: "<accessor>" };
    }
    return result;
  }
  return { $repr: describe(value, limit) };
}

const NON_ASCII = /[\u0080-￿]/g;

/**
 * Compact JSON with every non-ASCII character escaped, like Python's `ensure_ascii`.
 * Only for values built by this package, never for the target's objects.
 */
export function asciiJson(value: JsonValue | Record<string, unknown>): string {
  const text = JSON.stringify(value);
  return text.replace(NON_ASCII, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** Whether parsed JSON stays within `maximum` levels of nesting. */
export function withinDepth(value: unknown, maximum = MAX_DEPTH, depth = 0): boolean {
  if (typeof value !== "object" || value === null) {
    return true;
  }
  if (depth >= maximum) {
    return false;
  }
  const items = Array.isArray(value) ? value : Object.values(value);
  return items.every((item) => withinDepth(item, maximum, depth + 1));
}

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
export const MAX_ERROR_TYPE = 128;

/** A class name fit for a failure fingerprint, read without running getters. */
export function safeErrorType(error: unknown): string {
  if (!types.isNativeError(error) || types.isProxy(error)) {
    return "Error";
  }
  const own = dataString(error, "name");
  if (own !== undefined) {
    return validName(own);
  }
  const prototype = Object.getPrototypeOf(error) as object | null;
  const constructor = prototype === null ? undefined : Reflect.getOwnPropertyDescriptor(prototype, "constructor");
  if (constructor !== undefined && "value" in constructor && typeof constructor.value === "function") {
    const name = dataString(constructor.value as object, "name");
    if (name !== undefined) {
      return validName(name);
    }
  }
  return "Error";
}

function dataString(value: object, key: string): string | undefined {
  const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "string") {
    return undefined;
  }
  return descriptor.value;
}

function validName(name: string): string {
  return name.length <= MAX_ERROR_TYPE && IDENTIFIER.test(name) ? name : "Error";
}
