import assert from "node:assert/strict";
import { test } from "node:test";

import { GazuaAuthenticationError, GazuaRateLimited, reportUsage } from "../src/index.js";
import { lines, noSession, useSession } from "./helpers.js";

test("signals_are_typed_keyless_and_message_free", () => {
  noSession();
  assert.equal(reportUsage({ costUsd: 0.5 }), false);

  const files = useSession();
  assert.equal(reportUsage({ costUsd: 0.25 }), true);
  assert.equal(reportUsage({ costUsd: 1e-7 }), true);
  assert.throws(() => reportUsage({ costUsd: -1 }), RangeError);
  assert.throws(() => reportUsage({ costUsd: Number.NaN }), RangeError);
  const events = lines(files.events);
  assert.deepEqual(
    events.map((item) => [item["kind"], (item["payload"] as Record<string, unknown>)["cost_usd"]]),
    [
      ["usage", "0.25"],
      ["usage", "1e-7"],
    ],
  );
  const ids = events.map((item) => (item["payload"] as Record<string, string>)["usage_id"]);
  assert.ok(ids.every((id) => /^[0-9a-f]{32}$/.test(id ?? "")));
  assert.notEqual(ids[0], ids[1]);

  const limited = new GazuaRateLimited(2);
  assert.equal(limited.retryAfter, 2);
  assert.equal(new GazuaRateLimited().retryAfter, null);
  assert.equal(new GazuaRateLimited(10_000).retryAfter, 3600);
  assert.throws(() => new GazuaRateLimited(Number.POSITIVE_INFINITY), RangeError);
  const refused = new GazuaAuthenticationError();
  assert.deepEqual(Object.keys(refused), ["name"]);
  assert.ok(!refused.message.toLowerCase().includes("key="));
  noSession();
});
