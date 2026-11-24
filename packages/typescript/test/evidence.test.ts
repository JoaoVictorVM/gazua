import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { wrap } from "../src/index.js";
import { lines, noSession, tool, useSession } from "./helpers.js";

const RECORD_KEYS = [
  "schema_version",
  "seq",
  "tool",
  "arguments",
  "truncated",
  "actor",
  "dry_run",
  "undeclared",
  "outcome",
  "low_fidelity",
  "result_type",
  "error",
  "block_reason",
  "injection",
];

test("writes_python_valid_call_records_in_order", async () => {
  const files = useSession({ tools: { echo: tool(), fail: tool(), slow: tool() } });
  const tools = wrap({
    echo: (args: { text: string }) => args.text,
    fail: () => {
      throw new SyntaxError("secret message");
    },
    slow: async () => "late",
  });
  const pending = tools.slow();
  tools.echo({ text: "café \ud800" });
  assert.throws(() => tools.fail());
  assert.equal(await pending, "late");
  assert.throws(() => (tools.echo as unknown as (a: number, b: number) => unknown)(1, 2));
  const content = readFileSync(files.calls, "utf-8");
  // ASCII only, one complete line per record, like Python's ensure_ascii.
  assert.match(content, /^[\x00-\x7f]*$/);
  assert.ok(!content.includes("secret message"));
  const records = lines(files.calls);
  assert.deepEqual(
    records.map((item) => item["seq"]),
    [1, 2, 3, 4],
  );
  for (const record of records) {
    assert.deepEqual(Object.keys(record).sort(), [...RECORD_KEYS].sort());
    assert.equal(record["schema_version"], 1);
  }
  assert.deepEqual(
    records.map((item) => [item["tool"], item["outcome"]]),
    [
      ["echo", "returned"],
      ["fail", "raised"],
      ["slow", "returned"],
      ["echo", "blocked"],
    ],
  );
  assert.deepEqual(records[1]?.["error"], { type: "SyntaxError" });
  assert.equal(records[3]?.["block_reason"], "tool_arguments_unsupported");
  noSession();
});

test("captures_only_native_json_returns_with_limits", () => {
  const files = useSession({ tools: { plain: tool(), getter: tool(), custom: tool(), cyclic: tool(), huge: tool() } });
  let getterRuns = 0;
  const withGetter = {
    get value(): string {
      getterRuns += 1;
      return "computed";
    },
  };
  const custom = { toJSON: () => ({ leaked: true }) };
  const cyclic: Record<string, unknown> = {};
  cyclic["self"] = cyclic;
  const tools = wrap({
    plain: () => ({ order_id: "order-1", total: 42, tags: ["a"] }),
    getter: () => withGetter,
    custom: () => custom,
    cyclic: () => cyclic,
    huge: () => "x".repeat(70 * 1024),
  });
  tools.plain();
  tools.getter();
  tools.custom();
  tools.cyclic();
  tools.huge();
  assert.equal(getterRuns, 0);
  const returns = lines(files.returns);
  assert.deepEqual(returns[0]?.["original"], { order_id: "order-1", total: 42, tags: ["a"] });
  assert.deepEqual(
    returns.slice(1).map((item) => item["unavailable_reason"]),
    ["not_serializable", "not_serializable", "not_serializable", "too_large"],
  );
  assert.ok(returns.every((item) => item["execution_id"] === "GAZUA-exec-0001"));
  noSession();
});
