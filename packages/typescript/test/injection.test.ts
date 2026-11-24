import assert from "node:assert/strict";
import { test } from "node:test";

import { wrap } from "../src/index.js";
import { arm, disarm, resetDeliveries } from "../src/injection.js";
import { lines, noSession, tool, useSession } from "./helpers.js";

test("delivers_only_the_armed_text_turn_once", () => {
  const files = useSession({
    tools: { search_docs: tool(), structured: tool(), other: tool() },
    injections: [
      { id: "key#turn1", tool: "search_docs", text: "FIRST", max_deliveries: 1 },
      { id: "key#turn2", tool: "search_docs", text: "SECOND", max_deliveries: 1 },
      { id: "key#data", tool: "structured", text: "DATA", max_deliveries: 1 },
    ],
  });
  const tools = wrap({
    search_docs: () => "policy",
    structured: () => ({ result: "policy" }),
    other: () => "other",
  });
  arm("key#turn2");
  assert.equal(tools.other(), "other");
  assert.equal(tools.search_docs(), "policy\nSECOND");
  assert.equal(tools.search_docs(), "policy");
  disarm();
  arm("key#turn1");
  assert.equal(tools.search_docs(), "policy\nFIRST");
  disarm();
  arm("key#data");
  assert.deepEqual(tools.structured(), { result: "policy" });
  disarm();
  const injections = lines(files.calls).map((item) => item["injection"]);
  assert.deepEqual(injections, [
    null,
    { id: "key#turn2", delivered: true, reason: null },
    null,
    { id: "key#turn1", delivered: true, reason: null },
    { id: "key#data", delivered: false, reason: "unsupported_result_type" },
  ]);
  const returns = lines(files.returns);
  assert.equal(returns[1]?.["original"], "policy");
  assert.equal(returns[1]?.["delivered"], "policy\nSECOND");

  // A retry runs in a fresh runner, so its deliveries start again.
  resetDeliveries();
  arm("key#turn1");
  assert.equal(tools.search_docs(), "policy\nFIRST");
  disarm();
  noSession();
});
