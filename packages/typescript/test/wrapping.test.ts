import assert from "node:assert/strict";
import { test } from "node:test";

import { GazuaBlockedError, tool, UnsupportedToolError, wrap } from "../src/index.js";
import { setIdentityHook } from "../src/policy.js";
import { lines, noSession, tool as policy, useSession } from "./helpers.js";

test("preserves_container_and_function_behavior_outside_session", () => {
  noSession();
  const record = { get_order: (args: { id: string }) => args.id };
  const list = [function lookup() {
    return 1;
  }];
  const single = (args: { id: string }) => args.id;
  assert.equal(wrap(record), record);
  assert.equal(wrap(list), list);
  assert.equal(tool(single), single);
  assert.equal(tool({ name: "named" })(single), single);
  assert.equal(record.get_order({ id: "x" }), "x");

  useSession({ tools: { get_order: policy() } });
  const wrapped = wrap(record);
  assert.notEqual(wrapped, record);
  assert.deepEqual(Object.keys(wrapped), ["get_order"]);
  assert.notEqual(wrapped.get_order, record.get_order);
  assert.equal(record.get_order({ id: "kept" }), "kept");
  const objects = [{ name: "lookup", func: () => "found", description: "kept" }];
  const copied = wrap(objects);
  assert.notEqual(copied[0], objects[0]);
  assert.equal(copied[0]?.description, "kept");
  assert.notEqual(copied[0]?.func, objects[0]?.func);
  assert.throws(() => wrap([() => 1]), UnsupportedToolError);
  assert.throws(() => wrap({ pair: (left: number, right: number) => left + right }), UnsupportedToolError);
  noSession();
});

test("dry_run_never_calls_original", async () => {
  const files = useSession({
    tools: {
      refund: policy({ dry_run: true, has_dry_run_return: true, dry_run_return: "refund queued" }),
      unclassified: policy({ dry_run: true }),
    },
  });
  let effects = 0;
  const tools = wrap({
    refund: (_: { amount: number }) => {
      effects += 1;
      return "refunded";
    },
    unclassified: async () => {
      effects += 1;
      return "ran";
    },
    undeclared: () => {
      effects += 1;
      return "ran";
    },
  });
  assert.equal(tools.refund({ amount: 99 }), "refund queued");
  assert.equal(await tools.unclassified(), "ok");
  assert.equal(tools.undeclared(), "ok");
  assert.equal(effects, 0);
  const records = lines(files.calls);
  assert.deepEqual(
    records.map((item) => [item["tool"], item["dry_run"], item["undeclared"], item["low_fidelity"], item["outcome"]]),
    [
      ["refund", true, false, false, "returned"],
      ["unclassified", true, false, true, "returned"],
      ["undeclared", true, true, true, "returned"],
    ],
  );
  assert.deepEqual(records[0]?.["arguments"], { amount: 99 });
  noSession();
});

test("actor_arg_overwrites_object_without_mutating_input", async () => {
  const files = useSession({
    actor: { id: "attacker-1", role: "attacker" },
    tools: { get_order: policy({ actor_arg: "actor" }) },
  });
  const seen: Array<Record<string, unknown>> = [];
  const tools = wrap({
    get_order: async (args: { order_id: string; actor?: string }) => {
      seen.push({ ...args });
      return { order_id: args.order_id };
    },
  });
  const given = { order_id: "order-1", actor: "victim-1" };
  await tools.get_order(given);
  assert.deepEqual(given, { order_id: "order-1", actor: "victim-1" });
  assert.deepEqual(seen, [{ order_id: "order-1", actor: "attacker-1" }]);
  const [record] = lines(files.calls);
  assert.deepEqual(record?.["actor"], { id: "attacker-1", source: "actor_arg" });
  assert.deepEqual(record?.["arguments"], { order_id: "order-1", actor: "attacker-1" });
  const withoutArguments = tools.get_order as unknown as () => Promise<unknown>;
  await assert.rejects(withoutArguments(), GazuaBlockedError);
  assert.equal(lines(files.calls)[1]?.["block_reason"], "actor_arg_not_accepted");
  noSession();
});

test("as_user_restores_identity_after_sync_and_async_failures", async () => {
  const files = useSession({
    actor: { id: "attacker-1", role: "attacker" },
    as_user: "gazua_typescript:as_user",
    tools: { read: policy(), fail: policy(), slow_fail: policy() },
  });
  const identity: Array<string | null> = [null];
  setIdentityHook(<T>(actorId: string, invoke: () => T): T | Promise<T> => {
    identity.push(actorId);
    let result: T;
    try {
      result = invoke();
    } catch (error) {
      identity.pop();
      throw error;
    }
    if (result instanceof Promise) {
      return result.finally(() => identity.pop()) as Promise<T>;
    }
    identity.pop();
    return result;
  });
  const tools = wrap({
    read: () => identity.at(-1),
    fail: () => {
      throw new RangeError("boom");
    },
    slow_fail: async () => {
      await Promise.resolve();
      throw new TypeError("later");
    },
  });
  assert.equal(tools.read(), "attacker-1");
  assert.throws(() => tools.fail(), RangeError);
  await assert.rejects(tools.slow_fail(), TypeError);
  assert.deepEqual(identity, [null]);
  const records = lines(files.calls);
  assert.deepEqual(
    records.map((item) => [item["outcome"], (item["error"] as { type: string } | null)?.type ?? null]),
    [
      ["returned", null],
      ["raised", "RangeError"],
      ["raised", "TypeError"],
    ],
  );
  assert.ok(records.every((item) => JSON.stringify(item["actor"]) === '{"id":"attacker-1","source":"as_user"}'));

  // A hook that never runs the tool blocks the call; nothing ran.
  setIdentityHook((() => "skipped") as never);
  let ran = false;
  const skipped = wrap({ read: () => (ran = true) });
  assert.throws(() => skipped.read(), GazuaBlockedError);
  assert.equal(ran, false);
  noSession();
});
