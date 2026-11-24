import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { GazuaBlockedError, wrap } from "../src/index.js";
import { sessionState, SESSION_ENV } from "../src/session.js";
import { noSession, resetState, tool, useSession } from "./helpers.js";

test("rejects_invalid_or_unknown_sessions_closed", () => {
  noSession();
  assert.equal(sessionState(), null);

  const files = useSession({ tools: { get_order: tool() } });
  const state = sessionState();
  assert.equal(state?.kind, "session");
  assert.equal(state?.kind === "session" ? state.execution?.eventsPath : null, files.events);

  const reasons: Record<string, string> = {};
  const cases: Record<string, unknown> = {
    unknown_version: { ...JSON.parse('{"schema_version":3}') },
    extra_key: { extra: true },
    escaping_events: { events_path: "../events.jsonl" },
    windows_events: { events_path: "C:\\events.jsonl" },
    bad_actor_arg: { tools: { get_order: tool({ actor_arg: "not valid" }) } },
    bad_role: { actor: { id: "attacker-1", role: "admin" } },
  };
  for (const [name, change] of Object.entries(cases)) {
    useSession(change as Record<string, unknown>);
    const found = sessionState();
    assert.equal(found?.kind, "invalid", name);
    reasons[name] = found?.kind === "invalid" ? found.reason : "";
  }
  assert.equal(reasons["unknown_version"], "session_version");
  assert.equal(reasons["extra_key"], "session_invalid");

  resetState();
  process.env[SESSION_ENV] = files.session;
  writeFileSync(files.session, "{not json");
  assert.deepEqual(sessionState(), { kind: "invalid", reason: "session_malformed" });

  resetState();
  writeFileSync(files.session, JSON.stringify({ schema_version: 2 }).padEnd(1024 * 1024 + 1, " "));
  assert.deepEqual(sessionState(), { kind: "invalid", reason: "session_too_large" });

  resetState();
  const folder = join(files.folder, "folder-session");
  mkdirSync(folder);
  process.env[SESSION_ENV] = folder;
  assert.deepEqual(sessionState(), { kind: "invalid", reason: "session_not_regular" });

  resetState();
  process.env[SESSION_ENV] = "relative/session.json";
  assert.equal(sessionState()?.kind, "invalid");

  // A session that is present but untrusted blocks every tool before it runs.
  let calls = 0;
  const tools = wrap({ get_order: () => (calls += 1) });
  assert.throws(() => tools.get_order(), GazuaBlockedError);
  assert.equal(calls, 0);
  noSession();
});
