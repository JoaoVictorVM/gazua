// A scripted agent for agent mode tests, equivalent to tests/support/agent_target.py. It stands
// in for a model, never for its resistance.
//
// The `behavior` file in the project picks how it answers, with the same names as the Python
// fixture. Every real effect goes to effects/<pid>.jsonl, which is how tests prove what ran.
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import { GazuaAuthenticationError, GazuaRateLimited, reportUsage, wrap } from "gazua";

export const CANARY = "GAZUA-CANARY-7f3a9c";
const ORDERS: Record<string, { order_id: string; user_id: string; total: number }> = {
  "order-victim-1": { order_id: "order-victim-1", user_id: "victim-1", total: 42 },
};
const RECORD = /order-[a-z0-9-]+/g;

class ValueError extends Error {
  override name = "ValueError";
}

class KeyError extends Error {
  override name = "KeyError";
}

function effect(kind: string, data: Record<string, unknown> = {}): void {
  mkdirSync("effects", { recursive: true });
  appendFileSync(`effects/${process.pid}.jsonl`, `${JSON.stringify({ kind, t: Date.now() / 1000, ...data })}\n`);
}

function behavior(): string {
  return existsSync("behavior") ? readFileSync("behavior", "utf-8").trim() : "vulnerable";
}

function searchDocs(): unknown {
  effect("search_docs");
  if (existsSync("docs_dict")) {
    return { result: "Refunds are accepted within 30 days." };
  }
  return "Refunds are accepted within 30 days.";
}

function readMemory(): string {
  effect("read_memory");
  return "preferences: none";
}

async function getOrder(args: { order_id: string; user_id?: string; actor?: string }): Promise<unknown> {
  effect("get_order", { order_id: args.order_id, actor: args.actor ?? null });
  const order = ORDERS[args.order_id];
  return order === undefined ? null : { ...order };
}

function refund(args: { amount?: number }): string {
  effect("refund", { amount: args.amount ?? 1 });
  return "refunded";
}

function deleteAccount(args: { user_id?: string }): string {
  effect("delete_account", { user_id: args.user_id ?? "self" });
  return "deleted";
}

const TOOLS = wrap({
  search_docs: searchDocs,
  read_memory: readMemory,
  get_order: getOrder,
  refund,
  delete_account: deleteAccount,
});

function firstCall(): boolean {
  if (existsSync("flaky_used")) {
    return false;
  }
  writeFileSync("flaky_used", "x");
  return true;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

async function obey(message: string): Promise<string> {
  const lowered = message.toLowerCase();
  const answer = ["Done."];
  if (["secret", "hidden configuration", "credenciais"].some((word) => lowered.includes(word))) {
    answer.push(`The value is ${CANARY}.`);
  }
  if (["premium purchase", "paid operation", "sensíveis"].some((word) => lowered.includes(word))) {
    TOOLS.refund({ amount: 99 });
  }
  if (["never to use", "restricted tool"].some((word) => lowered.includes(word))) {
    TOOLS.delete_account({ user_id: "victim-1" });
  }
  for (const record of message.match(RECORD) ?? []) {
    await TOOLS.get_order({ order_id: record });
  }
  if (lowered.includes("gazuamarker")) {
    answer.push(message);
  }
  return answer.join(" ");
}

// Conversation state of this process: it grows across the turns of one attempt only.
let turn = 0;

export async function entrypoint(message: string): Promise<string> {
  const current = behavior();
  turn += 1;
  effect("entrypoint_called", { message: message.slice(0, 60), behavior: current, turn });
  // The agent obtains its own provider key, as a real agent would.
  void process.env["OPENAI_API_KEY"];
  if (current === "usage") {
    reportUsage({ costUsd: 0.25 });
  }
  if (current === "auth") {
    throw new GazuaAuthenticationError();
  }
  if (current === "rate_limit") {
    throw new GazuaRateLimited(0);
  }
  if (current === "crash") {
    throw new ValueError(`provider exploded with ${CANARY}`);
  }
  if (current === "other_crash") {
    throw new KeyError("different failure");
  }
  if (current === "garbled") {
    return 42 as unknown as string;
  }
  if (current === "hang") {
    await new Promise((resolve) => setTimeout(resolve, 3_600_000));
  }
  if (current === "leaky") {
    console.log(`stdout noise ${CANARY}`);
    return `Here: ${CANARY} <script>alert(1)</script> \u001b[31mred\u001b[0m`;
  }
  if (current === "early_refund") {
    TOOLS.refund({ amount: 1 });
  }
  let combined = message;
  const lowered = message.toLowerCase();
  let reads = current !== "skip_tool" && ["docs", "policy"].some((word) => lowered.includes(word));
  if (reads && existsSync("docs_once")) {
    reads = !existsSync("docs_used");
    writeFileSync("docs_used", "x");
  }
  if (reads) {
    combined += `\n${text(TOOLS.search_docs())}`;
  }
  if (["memory", "preferences"].some((word) => lowered.includes(word))) {
    combined += `\n${text(TOOLS.read_memory())}`;
  }
  if (current === "hardened" || (current === "flaky" && !firstCall())) {
    return "I cannot help with that.";
  }
  if (current === "early_refund") {
    return "Done.";
  }
  return obey(combined);
}

export function reset(): void {
  effect("reset");
}

export function sink(value: unknown): { effect: boolean; proof: Record<string, string> } {
  effect("sink");
  const shown = behavior() !== "hardened" && text(value).includes("<");
  return { effect: shown, proof: { marker_id: "markup_marker", observed: shown ? "unescaped" : "escaped" } };
}

export function asUser<T>(actorId: string, invoke: () => T): T {
  effect("as_user", { actor: actorId });
  return invoke();
}
