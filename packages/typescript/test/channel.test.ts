import assert from "node:assert/strict";
import { test } from "node:test";

import { GazuaBlockedError, wrap } from "../src/index.js";
import { lines, noSession, tool, useSession } from "./helpers.js";

test("ceiling_is_reserved_before_effect_and_latches", () => {
  const files = useSession({ max_tool_calls: 2, tools: { act: tool() } });
  const order: string[] = [];
  const tools = wrap({
    act: () => {
      order.push(`effect after ${lines(files.events).length} events`);
      return "done";
    },
  });
  assert.equal(tools.act(), "done");
  assert.equal(tools.act(), "done");
  assert.throws(() => tools.act(), (error: unknown) => error instanceof GazuaBlockedError && error.reason === "tool_call_ceiling");
  assert.throws(() => tools.act(), GazuaBlockedError);
  // Each effect happened only after its slot was announced; the ceiling came before the second.
  assert.deepEqual(order, ["effect after 1 events", "effect after 3 events"]);
  const events = lines(files.events);
  assert.deepEqual(
    events.map((item) => [item["seq"], item["kind"], item["payload"]]),
    [
      [1, "tool_call_admitted", { count: 1 }],
      [2, "tool_call_admitted", { count: 2 }],
      [3, "tool_call_ceiling", { count: 2 }],
    ],
  );
  assert.ok(events.every((item) => item["schema_version"] === 1 && item["execution_id"] === "GAZUA-exec-0001"));
  assert.equal(lines(files.calls).length, 2);
  noSession();
});
