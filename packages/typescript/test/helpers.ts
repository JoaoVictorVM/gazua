import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { clearCallLogs } from "../src/call-log.js";
import { clearChannels } from "../src/channel.js";
import { resetDeliveries } from "../src/injection.js";
import { clearSidecars } from "../src/observations.js";
import { resetAdmissions, setIdentityHook } from "../src/policy.js";
import { clearRegistry } from "../src/registry.js";
import { clearSessionCache, SESSION_ENV } from "../src/session.js";

export interface SessionFiles {
  readonly folder: string;
  readonly session: string;
  readonly calls: string;
  readonly events: string;
  readonly returns: string;
}

export function tool(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { dry_run: false, actor_arg: null, has_dry_run_return: false, dry_run_return: null, ...overrides };
}

/** Writes a version 2 session in a fresh folder and puts it in force. */
export function useSession(overrides: Record<string, unknown> = {}): SessionFiles {
  resetState();
  const folder = mkdtempSync(join(tmpdir(), "gazua-ts-"));
  const document = {
    schema_version: 2,
    run_id: "GAZUA-run-test",
    mode: "agent",
    call_log: "calls.jsonl",
    actor: null,
    as_user: null,
    tools: {},
    injections: [],
    execution_id: "GAZUA-exec-0001",
    max_tool_calls: 50,
    events_path: "events.jsonl",
    receiver: null,
    usage_reporting: true,
    ...overrides,
  };
  const session = join(folder, "session.json");
  writeFileSync(session, JSON.stringify(document));
  process.env[SESSION_ENV] = session;
  return {
    folder,
    session,
    calls: join(folder, "calls.jsonl"),
    events: join(folder, "events.jsonl"),
    returns: join(folder, "returns.private.jsonl"),
  };
}

export function noSession(): void {
  resetState();
  delete process.env[SESSION_ENV];
}

export function resetState(): void {
  clearSessionCache();
  clearCallLogs();
  clearChannels();
  clearSidecars();
  clearRegistry();
  resetAdmissions();
  resetDeliveries();
  setIdentityHook(null);
}

export function lines(path: string): Array<Record<string, unknown>> {
  let content: string;
  try {
    content = readFileSync(path, "utf-8");
  } catch {
    return [];
  }
  return content
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}
