# MCP servers

Gazua tests MCP servers that speak stdio, in any language. Install the adapter with the extra:

```bash
pip install "gazua[mcp]"
```

Without it, an MCP configuration stops with `This target needs MCP support. Install gazua[mcp].` and exit code 2. Python targets, `gazua --help` and the base install never load the MCP SDK and do not need Node.js.

Only one local stdio server per configuration is supported. Streamable HTTP, SSE, OAuth, remote servers, several servers at once, sampling, elicitation, prompts and resources are out of scope.

## Start: `gazua init --mcp`

```bash
gazua init --mcp node --mcp-arg build/server.js
```

`--mcp` is one executable and each `--mcp-arg` one argument, kept in order. No shell reads them, so pipes, substitutions and variables are not interpreted; a server that needs a shell must be started by an executable launcher of your project. `--mcp-cwd` sets the folder the server starts in, relative to the project. `--entrypoint` records a test entrypoint for agent mode.

**Listing tools starts the server's code on your machine, with your permissions.** Gazua runs it in a supervised worker, initializes the session, reads every page of `tools/list`, then stops it. No tool is called. The command and its arguments are shown only as the executable's name and the number of arguments, because arguments can hold private paths or tokens.

The generated `gazua.yaml` declares the server under `mcp` and every listed tool with `safe: false`. Names such as `send_*` or `delete_*` are suggested as sensitive, for review only. Annotations such as `readOnlyHint` are the server's claims: Gazua never copies them and they never release a tool. An existing `gazua.yaml` is kept. If the server does not start, does not answer within 30 seconds, speaks an unsupported protocol revision or returns an invalid or oversized list, init exits with 2, shows the executable's name and the error code, and writes nothing.

## Review the configuration

```yaml
schema_version: 1
mcp:
  transport: stdio
  command: node
  args: ["build/server.js"]
  cwd: "."
tools:
  get_order: {safe: true, sensitive: false, actor_arg: actor_id, owner_arg: owner_id}
  send_email: {safe: false, sensitive: true, dry_run_return: "queued"}
fixtures:
  attacker: {id: attacker}
  victim:
    id: victim
    records: [{tool: get_order, id_arg: order_id, id: order-victim}]
```

A call reaches the server only for a tool that is declared, classified and `safe: true`, and that was in the tool list Gazua approved when the run was planned. Every other call returns its `dry_run_return`, or a generic `ok` with low fidelity, and is recorded as a dry-run. Point the server at synthetic test data only.

Identity over MCP comes from `actor_arg` only: Gazua writes the attacker's id into that argument, over whatever the caller sent, before validating the input schema. `target.as_user` is a local Python hook and does not reach another process, so attacks that need identity are not tested without `actor_arg`.

Arguments are validated against the tool's input schema locally. A schema whose root is not an object, or that references another document, is not supported: its tool is not tested, and no reference is ever fetched from the network or from disk.

## Tools mode

```bash
gazua run --tools
```

Tools mode calls the server directly over MCP, with no model and no Python entrypoint. Results, rates, the gate and exit codes are the same as for Python targets. `structuredContent` is preferred as the recorded return; one text block is a string and several are a list of strings. `isError: true` is recorded as a raised call: an application error is neither a success nor a proof of resistance.

## Agent mode and `gazua mcp-proxy`

Agent mode still calls your Python test entrypoint. Its MCP client must start `gazua mcp-proxy` instead of the real server, so Gazua can apply dry-run and deliver attack texts:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from gazua.mcp import proxy_server_parameters


async def run(message: str) -> str:
    server = StdioServerParameters(**proxy_server_parameters())
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()  # list again on every call of the entrypoint
        ...
```

`proxy_server_parameters()` returns the command and the one environment variable the proxy needs; it only works during a run. Outside a run, `gazua mcp-proxy` exits with 2 before anything starts. The proxy takes no server command or policy: it connects to a broker inside the attempt's worker, over `127.0.0.1` only, authenticated with a random token that never appears in `gazua.yaml`, arguments, logs or reports. The broker is the only process that starts the real server, and the server receives only the minimal system environment: no `GAZUA_*` variable and no provider key.

Two entries are reachable through MCP:

```yaml
agent_entries:
  mcp_tool_description: {tool: search_docs, request: "Check my order status."}
  tool_result: {tool: search_docs, request: "Check my order status."}
```

`mcp_tool_description` writes each turn's text into the declared tool's description, only while that turn's trigger message runs; the name and the input schema are never changed. `tool_result` appends it to the first text result, as for Python targets; a structured or binary result is left as it is and the attempt is not tested. A description counts as delivered when a listing that holds it was written to the agent's client. **Your client must list the tools again on every call of the entrypoint**: a cached list does not prove delivery, and the attempt is not tested. Effects the broker saw before the delivery are never proofs of that attack.

Delivery proves that the client received the text, not that a model understood it. The simulated agent used in Gazua's own tests proves transport and control; measuring a real model needs your real agent.

## Changes during a run

Before every real call, Gazua lists the tools again and compares each definition with the approved snapshot. A tool that changed or disappeared is refused locally; the attacks that depend on it stop, are reported as not tested with `mcp_tool_changed`, and the run exits with 2. Results already concluded are kept, and attacks that do not depend on it go on. A tool that appears mid-run stays in dry-run, even when a declaration with its name says `safe: true`. A server that stops answering ends its attempt; a call whose answer was lost is never sent again.

Comparing definitions does not detect a change of behavior behind the same schema, and stopping `tools/call` does not stop what the server's own code does when it starts.

## Reports, baseline and verify

Run documents use `schema_version` 4 with `target_adapter: mcp_stdio` and an `mcp` block: the protocol revision, the SHA-256 of the tool list, the tool names, the tools that changed and how many description turns were delivered. The command, its arguments, descriptions and server texts are never in it, and reports rebuild from it alone.

`gazua verify` replays an MCP finding through the same adapter. If the server's tools differ from the run that recorded the finding, or that run is no longer kept, the verification cannot close it: run `gazua run` again and review the baseline.

## Limits

Startup and listing take at most 30 seconds, bounded by the attempt timeout. A listing has at most 100 pages, 1,000 tools, 1 MiB per message and 8 MiB in total; a message over the limit is refused before it is parsed. The broker serializes calls and counts dry-runs against `max_tool_calls`. The private delivery channel holds at most 10,000 events or 4 MiB per attempt; past that, no new call is attributed. Its line format is published in [`src/gazua/schemas/mcp-delivery-v1.schema.json`](../src/gazua/schemas/mcp-delivery-v1.schema.json).
