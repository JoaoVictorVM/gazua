/**
 * Gazua for TypeScript agents: wraps the agent's tools so the Gazua CLI can run its attacks
 * with dry-run, imposed identity and call evidence. Outside a Gazua run everything here is a
 * no-op that returns what it received.
 */

export { GazuaBlockedError, UnsupportedToolError } from "./errors.js";
export { GazuaAuthenticationError, GazuaRateLimited, reportUsage } from "./telemetry.js";
export { tool, type ToolOptions, wrap } from "./wrapping.js";
export type { AsUserHook } from "./policy.js";
export type { Entrypoint, OutputSink, ResetHook } from "./target.js";
export type { ToolFunction } from "./registry.js";

/** What an output sink returns: whether the output had an effect, and JSON proof of it. */
export interface SinkResult {
  readonly effect: boolean;
  readonly proof: { readonly [key: string]: unknown };
}
