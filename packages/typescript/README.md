# gazua (npm)

Wraps the tools of a TypeScript agent so the [Gazua](https://github.com/JoaoVictorVM/gazua) CLI
can run its attacks in agent mode, with the same dry-run, identity and call evidence as the
Python package. The command, the verdicts and the reports stay in the Python CLI.

Requires Node.js 22 or newer and the Python package `gazua` of the same version.

```sh
npm install --save-dev gazua
pip install gazua
```

## Test entrypoint

```ts
import { wrap, GazuaRateLimited } from "gazua";
import { tools } from "./tools.js";
import { createAgent } from "./agent.js";

const agent = createAgent({ tools: wrap(tools) });

export async function respond(message: string): Promise<string> {
  return agent.reply(message);
}
```

Build it to JavaScript ESM (`tsc`), then declare it in `gazua.yaml`:

```yaml
schema_version: 1
typescript:
  module: dist/gazua-test.js
  entrypoint_export: respond
tools:
  get_order: {safe: true, sensitive: false, actor_arg: actor_id}
  send_email: {sensitive: true, dry_run_return: "ok"}
```

and run `gazua run --agent`. Outside a Gazua run, `wrap` and `tool` return exactly what they
received, so the entrypoint costs nothing in production.

A tool takes no argument or one plain object of named arguments during a run. Tools that are
not declared, not classified or not `safe: true` never run: they return their dry-run value.

See the [TypeScript guide](https://github.com/JoaoVictorVM/gazua/blob/main/docs/typescript.md)
for hooks, limits and troubleshooting. Apache-2.0.
