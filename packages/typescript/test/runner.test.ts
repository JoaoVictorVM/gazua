import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parseLine, ProtocolError, validate } from "../src/protocol.js";
import { useSession } from "./helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BUILT_SOURCE = join(HERE, "..", "src");
const CORPUS = join(HERE, "..", "..", "test", "fixtures", "protocol-corpus.json");

interface Outcome {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function project(): { folder: string; session: string } {
  const files = useSession({ tools: { lookup: { dry_run: false, actor_arg: null, has_dry_run_return: false, dry_run_return: null } } });
  writeFileSync(join(files.folder, "package.json"), JSON.stringify({ type: "module" }));
  const index = pathToFileURL(join(BUILT_SOURCE, "index.js")).href;
  writeFileSync(
    join(files.folder, "agent.js"),
    [
      `import { wrap } from ${JSON.stringify(index)};`,
      "const tools = wrap({ lookup: () => 'found' });",
      "export function respond(message) {",
      "  console.log('noise from the target');",
      "  process.stdout.write('more noise\\n');",
      "  return `${message}:${tools.lookup()}`;",
      "}",
      "export const notCallable = 1;",
    ].join("\n"),
  );
  return { folder: files.folder, session: files.session };
}

function run(folder: string, session: string, input: string): Promise<Outcome> {
  const runner = pathToFileURL(join(BUILT_SOURCE, "runner.js")).href;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", `import { main } from ${JSON.stringify(runner)}; main();`], {
      cwd: folder,
      env: { ...process.env, GAZUA_SESSION: session },
      shell: false,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf-8")));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf-8")));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
  });
}

function open(id: string, entrypoint = "respond"): string {
  return JSON.stringify({
    protocol_version: 1,
    type: "open",
    request_id: id,
    operation: "run",
    module: "agent.js",
    exports: { entrypoint, reset: null, as_user: null, output_sink: null },
  });
}

function invoke(id: string, message: string): string {
  return JSON.stringify({ protocol_version: 1, type: "invoke", request_id: id, message, armed_injection_id: null });
}

test("protocol_is_bounded_ordered_and_stdout_exclusive", async () => {
  const { folder, session } = project();

  const normal = await run(folder, session, [open("1"), invoke("2", "hello"), JSON.stringify({ protocol_version: 1, type: "close", request_id: "3" }), ""].join("\n"));
  assert.equal(normal.code, 0);
  const answers = normal.stdout.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.deepEqual(answers.map((item) => item["type"]), ["ready", "result", "closed"]);
  assert.deepEqual(answers[0]?.["tools"], [{ name: "lookup", supports_sync: true, supports_async: false, argument_style: "none", ambiguous: false }]);
  assert.equal(answers[1]?.["response"], "hello:found");
  for (const line of normal.stdout.trim().split("\n")) {
    validate("to_python", parseLine(Buffer.from(line)));
  }
  assert.ok(normal.stderr.includes("noise from the target"));
  assert.ok(!normal.stdout.includes("noise"));

  // A request id that does not grow ends the runner without another line.
  const repeated = await run(folder, session, [open("1"), invoke("1", "again"), ""].join("\n"));
  assert.equal(repeated.code, 65);
  assert.equal(repeated.stdout.trim().split("\n").length, 1);

  // Nothing but open is accepted first, and nothing is imported before it.
  const early = await run(folder, session, `${invoke("1", "hello")}\n`);
  assert.equal(early.code, 65);
  assert.equal(early.stdout, "");

  const extra = await run(folder, session, `${JSON.stringify({ ...JSON.parse(open("1")), extra: 1 })}\n`);
  assert.equal(extra.code, 65);

  const long = await run(folder, session, `${"x".repeat(1024 * 1024 + 10)}\n`);
  assert.equal(long.code, 65);
  assert.equal(long.stdout, "");

  const notCallable = await run(folder, session, `${open("1", "notCallable")}\n`);
  assert.deepEqual(JSON.parse(notCallable.stdout), {
    protocol_version: 1,
    type: "error",
    request_id: "1",
    code: "export_not_callable",
    error_type: null,
    retry_after: null,
  });
});

interface CorpusCase {
  readonly direction: "to_runner" | "to_python";
  readonly line: string;
  readonly valid: boolean;
}

test("python_and_npm_accept_the_same_protocol_corpus", () => {
  const cases = JSON.parse(readFileSync(CORPUS, "utf-8")) as CorpusCase[];
  assert.ok(cases.length > 20);
  for (const item of cases) {
    let accepted = true;
    try {
      const value = parseLine(Buffer.from(item.line, "utf-8"));
      if (item.direction === "to_runner") {
        validate("to_runner", value);
      } else {
        validate("to_python", value);
      }
    } catch (error) {
      assert.ok(error instanceof ProtocolError, item.line);
      accepted = false;
    }
    assert.equal(accepted, item.valid, `${item.direction}: ${item.line.slice(0, 120)}`);
  }
});
