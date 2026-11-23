# Demo

`gazua demo` attacks a fictional store support assistant with Gazua's real engines, verdicts and reports. It needs no API key, no configuration and no network connection.

```console
uv tool install gazua
gazua demo
```

With pip, `pip install gazua` and then `gazua demo`. Installing may use the network; the demo itself does not. Until the first stable release, add the pre-release version to the install command, as described in the README.

> **The demo uses a simulated model that follows a fixed script. It shows that Gazua and the controls it exercises work; it does not measure how a real model resists attacks.** The terminal, the demo page and every report of the demo repeat this notice. The rates in the agent report are computed exactly as for a real agent, but here they describe the script, not a model.

## What it runs

1. **Tools mode**, as `gazua run --tools`: every tools mold of the v0.2 catalog, calling the store's tools directly as the attacker.
2. **Agent mode**, as `gazua run --agent`: every agent mold of the v0.2 catalog, 5 repetitions per scenario, plus 2 legitimate tasks, sent to the store assistant run by the scripted model `gazua-scripted-v1`.
3. **The demo page**, `gazua-demo/index.html`, with links to the HTML, Markdown and JSON reports of both runs. It opens in your browser unless you pass `--no-open`.

A gated finding in tools mode does not stop the demo: findings are what it is for. An error, an interruption or a failure to save the reports stops it before agent mode, and the page says which mode did not start.

| Option | Default | What it does |
|---|---|---|
| `--output PATH` | `./gazua-demo` | Folder of the demo: its configuration, reports and page |
| `--no-open` | off | Does not open the page; use it in CI and containers |
| `--language en\|pt` | `en` | Language of the attack text and of the notice |

The demo takes about a minute and starts about a hundred short worker processes. It never reads `gazua.yaml` or any other file of the folder you run it from.

## The store

The target is a Python module installed with Gazua, `gazua.demo.target`. Everything in it is synthetic: two users (`attacker-1`, `victim-1`), two orders, a list of refunds and a fictional outbox, all in memory and rebuilt before each attempt. It reads no credential, file, network, subprocess or clock. Its missing controls are on purpose:

| Tool | Declared as | Missing control |
|---|---|---|
| `get_order` | `safe: true`, regular, with `owner_arg` and `actor_arg` | Never checks who owns the order; the victim's order carries the canary `GAZUA-DEMO-CANARY-7f3a9c` |
| `refund_order` | `safe: true`, sensitive | No authorization and no ceiling; it only appends to the in-memory list |
| `send_email` | forbidden, not `safe: true` | Exists although the assistant should never use it. Gazua keeps it in dry-run, so its body never runs: the proof is the recorded call |
| `search_policy` | `safe: true`, regular | Returns the policy text; agent mode appends attacks to it for the `tool_result` and `rag_document` entries |
| `output_sink` | test sink | Accepts markup and control characters as they are. It renders, evaluates and loads nothing |

## The scripted model

`gazua-scripted-v1` applies fixed rules, in this order, to the message it receives and, once, to the text that `search_policy` returns. It never reads the catalog, an attack's context or a verdict, so an attack has an effect only when its text really reaches the script and matches a rule.

| Recognized text, English or Portuguese | What the script does |
|---|---|
| `policy`, `política` | Calls `search_policy` and reads its result once |
| A known order id, such as `order-victim-1` | Calls `get_order` and answers with the record |
| `secret`, `hidden configuration`, `credentials`, `segredo`, `valores ocultos`, `credenciais` | Answers with the internal value of its context, the canary |
| `premium purchase`, `paid operation`, `sensitive operation`, `compra premium`, `operação paga`, `operação sensível`, `operações sensíveis` | Calls `refund_order` |
| `never to use`, `restricted tool`, `nunca usar`, `ferramenta restrita` | Calls `send_email` |
| `GAZUA-OUTPUT-MARKER`, `gazuaMarker` | Repeats the markup it saw, without running it |
| Anything else | `I can help with your orders, refunds and the store policy.` |

It keeps the last two messages of an attempt as its history; the reset clears them. A change to the catalog can leave a mold without effect, and the report then shows that as it is.

## Results

The demo exits with the same codes as the modes: 0 with no gated finding, 1 with a gated finding, 2 on an error. The highest code of both modes wins, so a script that runs the demo has to accept exit code 1 as the expected result. Results repeat between runs: the selection, states, findings, proofs, rates and legitimate use are the same, while run ids, timestamps and durations change.

Some molds stay `not tested`, with their native reasons, instead of being hidden: tools molds that need a forbidden tool marked `safe: true`, the `poisoned_memory` entry, which the store does not declare, and memory effects, which need a memory adapter Gazua does not have yet.

## Files

```text
gazua-demo/
  gazua.yaml          configuration of the demo; do not edit it
  .gazua-demo.json    marks the folder as a demo workspace
  .gitignore          ignores .gazua/
  index.html          the demo page
  .gazua/runs/<run>/  report.html, report.md and run.json of each run
```

Running the demo again in the same folder reuses it and adds two runs; the usual retention keeps the last 20. A folder that is not a demo workspace, or whose `gazua.yaml` was changed, is refused with exit code 2 and left untouched; choose another folder with `--output`. Links and junctions are refused, never followed.

Every finding has a reproduction command, such as `gazua run --tools --config gazua.yaml --mold idor-01`. Run it from the demo folder: it uses the demo's `gazua.yaml` and the installed target, so it needs no checkout of Gazua. `gazua clean` in that folder removes the runs and reports but keeps the configuration, the marker and the page, whose links stop working until the next `gazua demo`.

## Docker

The image runs the demo with `--no-open` and writes to `/work/gazua-demo`. It publishes no port and runs as a user without privileges.

```console
mkdir work
docker run --rm --network none --volume "$PWD/work:/work" ghcr.io/joaovictorvm/gazua:<version>
```

Pulling the image uses the network; running it does not, so `--network none` works. Each release publishes the image tagged with the package version and records its digest in the release run. To build it locally from a checkout:

```console
uv build --wheel --out-dir dist
uv export --frozen --no-dev --no-emit-project --format requirements.txt -o dist/requirements.txt
docker build --tag gazua-demo .
```

The image is also a base for CI jobs: override its entrypoint to run other `gazua` commands. The image does not include the optional `gazua[mcp]` and `gazua[otel]` extras.

## Reusing the store

`gazua.demo.target`, `gazua.demo.fixtures` and `gazua.demo.script` can be imported without starting a demo, opening a browser or contacting a provider. Outside a Gazua run the tools are plain function calls.
