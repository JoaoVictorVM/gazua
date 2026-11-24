# TypeScript agents

Agent mode can attack an agent written in TypeScript with the same verdicts, statistics, gate and reports as a Python entrypoint. The npm package `gazua` wraps the agent's tools inside Node: it applies the same dry-run policy, imposes the attacker's identity when a tool allows it, delivers indirect attacks through text results and writes the same call log the Python wrapper writes. The command stays `gazua`, the Python CLI; it starts one Node runner per attempt and never reimplements a verdict in JavaScript.

Only agent mode reaches a TypeScript target in this release. `gazua run --tools` refuses it with `--tools does not run TypeScript tools yet; use --agent for a TypeScript target.` and exit code 2, without starting Node.

## Requirements

- Node.js 22 or newer, as the `node` your system resolves. No configuration, mold or environment variable chooses another command.
- The npm package installed in the tested project, with the same major and minor version as the Python package:

  ```bash
  npm install --save-dev gazua
  pip install gazua
  ```

- A test entrypoint compiled to JavaScript ESM (`.js` or `.mjs`). Gazua never runs `.ts` files, never picks a transpiler, never installs packages and never runs your build. Build the project before each run.

The npm package has no production dependency. Its root exports `wrap`, `tool`, `reportUsage`, `GazuaRateLimited`, `GazuaAuthenticationError`, `GazuaBlockedError` and the types of the hooks; `gazua/runner` is reserved to Gazua's launcher.

## Test entrypoint

Wrap the tools where your test entrypoint builds the agent, and export one function that sends a message and returns the agent's text answer:

```ts
// src/gazua-test.ts
import { wrap } from "gazua";
import { createAgent } from "./agent.js";
import { getOrder, sendEmail } from "./tools.js";

const agent = createAgent({ tools: wrap({ get_order: getOrder, send_email: sendEmail }) });

export async function respond(message: string): Promise<string> {
  return agent.reply(message);
}
```

`wrap` accepts a record from tool name to function, an array or tuple of named functions, and tool objects with `name` and `func`. It keeps the shape and order of the container and copies tool objects instead of changing them. An anonymous function in an array has no name, so it is refused.

`tool` marks one function, with its own name or with an explicit one:

```ts
import { tool } from "gazua";

export const getOrder = tool(async function get_order(args: { order_id: string; actor_id?: string }) {
  return orders.find(args.order_id, args.actor_id);
});
export const sendEmail = tool({ name: "send_email" })(async (args: { to: string; body: string }) => mailer.send(args));
```

Outside a Gazua run, `wrap` returns the very same container and `tool` the very same function, so production code that imports them behaves as before. Prefer `wrap` in a test entrypoint: then production code imports nothing from Gazua.

### Arguments

During a run a tool takes no argument or **one plain object** of named arguments. Any other call, such as two positional arguments, is blocked before the tool runs, with `tool_arguments_unsupported` in the call log. This keeps `actor_arg` and the evidence unambiguous. Sync and async functions are both accepted; a tool that returns a value keeps returning it, and one that returns a promise keeps returning a promise.

## Configuration

```yaml
schema_version: 1
typescript:
  module: dist/gazua-test.js
  entrypoint_export: respond
  reset_export: reset            # optional
  as_user_export: asUser         # optional
  output_sink_export: observeOutput  # optional
tools:
  get_order: {safe: true, sensitive: false, actor_arg: actor_id}
  send_email: {sensitive: true, dry_run_return: "ok"}
fixtures:
  attacker: {id: attacker-1}
  victim:
    id: victim-1
    records: [{tool: get_order, id_arg: order_id, id: order-victim-1}]
canaries: ["GAZUA-CANARY-7f3a9c"]
```

`module` is relative to the `gazua.yaml` folder: a regular `.js` or `.mjs` file inside the project, reached without symbolic links, URLs, package names, `..` or a drive. The exports are JavaScript identifiers. `typescript` excludes `entrypoint`, `mcp` and `http`; the Python hooks `target.reset`, `target.as_user` and `output_sink` cannot be declared with it, because the hooks live in the module. Traces do not apply.

The tool declarations are the same as for Python. A tool that is not declared, not classified or not `safe: true` stays in dry-run: the original function is never called and the tool returns its `dry_run_return`, or `"ok"` marked as low fidelity.

## Start: `gazua init --typescript`

```bash
npm run build
gazua init --typescript dist/gazua-test.js --typescript-export respond
```

Init checks Node and the module, warns that the module will be imported, and starts the runner in a supervised worker to list the tools registered by `wrap` and `tool`. Neither the entrypoint nor any tool is called. It writes a conservative `gazua.yaml` where every tool is `safe: false` until you review it. `--typescript-reset`, `--typescript-as-user` and `--typescript-output-sink` record the optional hooks. Combining `--typescript` with `--entrypoint`, `--mcp` or `--http` fails before Node starts.

## Running

```bash
gazua run --agent --quick
```

Before the preview, the run checks Node, the package, the protocol, the module, its exports and the tool inventory; a declared agent entry whose tool the module does not register is an error. The preview names the Node and npm package versions. Then selection, quick, repetitions, legitimate tasks, budget, retries and the stop policy work exactly as for a Python entrypoint, and the run writes the same reports.

Each attempt runs in its own supervised worker, which starts one Node runner. Every turn of a multi-turn attack goes to the same runner, so the agent keeps its conversation state between turns. A retry, another repetition or a legitimate task always gets a new runner, with nothing left from the previous one. Node is a descendant of the worker: a timeout, a ceiling, Ctrl+C or a cancelled run kills its whole process tree.

## Hooks

| Export | Receives | Returns | Rule |
|---|---|---|---|
| `entrypoint_export` | one message string | a string or a promise of one | Called for every turn |
| `reset_export` | nothing | nothing or a promise | Runs before each attempt in that attempt's runner, and once more at the end of the run. Runs one attempt at a time |
| `as_user_export` | the actor id and a callback | what the callback returns | Runs a tool as a user for tools without `actor_arg`. It must call the callback once and restore the identity even when it throws |
| `output_sink_export` | the agent's output, as JSON data | `{effect, proof}` | `proof` is a non-empty JSON object naming its marker |

```ts
export async function asUser<T>(actorId: string, invoke: () => T): Promise<T> {
  const previous = session.user;
  session.user = await users.load(actorId);
  try {
    return await invoke();
  } finally {
    session.user = previous;
  }
}
```

A hook that throws is reported by its class name only. A reset that fails stops the run with `reset_failed`, as for Python. An identity hook that fails or never runs the tool blocks that call. A sink that fails or answers with another shape leaves the attack not tested, never resisted.

## Signals

The entrypoint uses its own model, configuration and key; Gazua never reads `process.env`, credential files or SDK objects. It can report three things:

```ts
import { GazuaAuthenticationError, GazuaRateLimited, reportUsage } from "gazua";

reportUsage({ costUsd: 0.0021 });            // increment since the last report
throw new GazuaRateLimited(2);              // the provider answered 429; wait 2 seconds
throw new GazuaAuthenticationError();       // the provider refused the credential
```

`reportUsage` returns `false` and does nothing outside a run. A rate limit is retried with backoff and stops the run when it persists; an authentication failure stops the run at once and keeps the partial report. Any other error counts by its class name toward the repeated failure stop.

## Evidence and privacy

The runner writes the same files as the Python wrapper, in the attempt's private folder: the call log (`call-record-v1`), the events that announce each tool call before it runs and the reported usage, and the private returns the verdicts read and the engine deletes. Return values and errors never reach the call log, only their type. Arguments are copied as JSON data without running getters, `toJSON` or custom inspection, and long values are cut. An injection reaches only a string result of the declared tool during its own turn; a structured result leaves the attack not tested.

Stdout carries only the runner's protocol. `console` and `process.stdout.write` calls of the target go to stderr, which the worker discards; a raw write to the stdout descriptor breaks the protocol and ends the attempt. Nothing the target prints reaches a report.

The run document, schema version 6, records `target_adapter: typescript` and the protocol, npm package and Node versions with the SHA-256 of the compiled module. It never records the module's path beyond the target reference, its source map, the working folder, the package manager or the module's content. `gazua report --from` rebuilds the reports from that document without starting Node.

## Baseline and verification

Finding ids do not include the language. `gazua verify` replays a TypeScript finding only against the same compiled module and the same npm package line, recorded in the newest kept run that holds the finding. After a rebuild that changed the module, the verification says it cannot close the finding; run `gazua run --agent` again and review the baseline. A module that changes in the middle of a run stops new attempts with `typescript_module_changed`.

## Limits

| Resource | Limit |
|---|---|
| Session file | 1 MiB |
| Protocol line | 1 MiB, 32 levels of nesting |
| Logged argument | 4,096 characters per field |
| Event | 64 KiB, 4,096 per attempt |
| Private return | 64 KiB each, 1 MiB per attempt |
| Pending requests | 1 |

The Node code you authorize runs with your permissions. The timeout and the tree kill bound it, but there is no operating system sandbox.

## Errors

| Message or code | Cause | Fix |
|---|---|---|
| `typescript_node_missing`, `typescript_node_unsupported` | No `node` on PATH, or older than 22 | Install Node.js 22 or newer |
| `typescript_package_missing` | The project has no `gazua` npm package | `npm install --save-dev gazua` |
| `typescript_package_incompatible` | The npm and Python packages differ in major or minor version | Install matching versions |
| `typescript_module_missing` | The compiled module does not exist | Build the project |
| `typescript_module_invalid`, `typescript_module_path_invalid` | Outside the project, a link, or not `.js`/`.mjs` | Point `module` at the compiled file inside the project |
| `typescript_module_import_failed` | Importing the module threw | Run the module with Node to see the error |
| `typescript_entrypoint_export_missing`, `typescript_hook_export_missing`, `typescript_export_not_callable` | A declared export is absent or not a function | Export the function under the declared name |
| `typescript_runner_exited`, `typescript_protocol_error` | The runner stopped, or the target wrote to the stdout descriptor | Remove raw stdout writes from the module |
| `typescript_module_changed` | The module changed during the run | Build before running, not during it |
