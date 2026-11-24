/**
 * Append-only event channel from the tested process to the Gazua supervisor, in the same
 * format as the Python wrapper. Each event is one complete JSON line written before the call
 * that produced it goes on.
 */

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { resolve } from "node:path";

import { asciiJson, type JsonValue } from "./json.js";
import type { ExecutionChannel } from "./session.js";

export const EVENT_SCHEMA_VERSION = 1;
export const MAX_EVENT_BYTES = 64 * 1024;
export const MAX_EVENTS = 4096;

/** An event could not be written. Callers fail closed. */
export class ChannelError extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

/** Appends one line and optionally asks the disk to keep it. */
export function appendLine(path: string, line: string, sync = false): void {
  const descriptor = openSync(path, "a");
  try {
    writeSync(descriptor, line);
    if (sync) {
      fsyncSync(descriptor);
    }
  } finally {
    closeSync(descriptor);
  }
}

/** Complete lines already in a file, so a second writer in the same execution continues the count. */
export function completeLines(path: string): number {
  if (!existsSync(path)) {
    return 0;
  }
  const content = readFileSync(path);
  let count = 0;
  for (const byte of content) {
    if (byte === 0x0a) {
      count += 1;
    }
  }
  return count;
}

export class EventChannel {
  private seq: number | null = null;

  constructor(
    readonly path: string,
    readonly executionId: string,
  ) {}

  /** Writes one event and returns its `seq`. `sync` also asks the disk to keep it. */
  emit(kind: string, payload: Record<string, JsonValue>, sync = false): number {
    let seq: number;
    try {
      seq = (this.seq ?? completeLines(this.path)) + 1;
    } catch {
      throw new ChannelError("channel_unavailable");
    }
    if (seq > MAX_EVENTS) {
      throw new ChannelError("channel_saturated");
    }
    const line = asciiJson({
      schema_version: EVENT_SCHEMA_VERSION,
      execution_id: this.executionId,
      seq,
      kind,
      payload,
    });
    if (line.length + 1 > MAX_EVENT_BYTES) {
      throw new ChannelError("event_too_large");
    }
    try {
      appendLine(this.path, `${line}\n`, sync);
    } catch {
      throw new ChannelError("channel_unavailable");
    }
    this.seq = seq;
    return seq;
  }
}

const channels = new Map<string, EventChannel>();

export function channelFor(execution: ExecutionChannel): EventChannel {
  const key = resolve(execution.eventsPath);
  let channel = channels.get(key);
  if (channel === undefined) {
    channel = new EventChannel(key, execution.executionId);
    channels.set(key, channel);
  }
  return channel;
}

export function clearChannels(): void {
  channels.clear();
}
