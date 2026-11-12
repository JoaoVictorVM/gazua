# Tools mode

`gazua run --tools` calls your tools directly, as the attacker, against the victim's test fixtures. It proves whether your code blocks the access, without a model in the loop. No provider key is needed, no model is called, and the same project gives the same results on every run, so it fits every pull request.

```console
gazua run --tools
gazua run --tools --mold idor-01
gazua run --tools --config tests/gazua.yaml --max-runs 100
```

## What it runs

The mode takes every mold of the catalog that supports `tools` and combines it with each tool that fits it:

| Action | Tools it uses |
|---|---|
| `call_forbidden` | Tools declared `forbidden: true` |
| `call_sensitive`, `repeat_sensitive_call` | Tools declared `sensitive: true` |
| `read_victim_record`, `probe_canary_return` | Tools that have a record under `fixtures.victim.records` |
| `probe_output_sink` | Every classified tool; only the constant marker goes to your `output_sink`, and the tool itself is not called |

Each tool, victim record and canary is a separate attack with its own result, so a finding on one record is never averaged with another. Each combination runs once: tools mode has no model, so repeating the same call adds nothing. `--mold` keeps one mold, by exact id, and runs all of its combinations.

Attacks that act as the attacker impose its identity through the tool's `actor_arg` or through `target.as_user`. Variants that leave the actor or the owner out on purpose call the tool without it; Gazua does not fill it in. Arguments come only from the fixtures and the declared argument names. When a required argument has no declared value, the combination is not tested and the missing argument is named.

## Only `safe: true` tools run

A tool is called only when all of these are true:

- `gazua.yaml` declares it `safe: true`;
- it is classified with `sensitive` or `forbidden`;
- it was registered when your test module was imported, under a name no other function uses.

Every other tool is listed before the first attack with the reason, and its attacks are reported as `not tested, missing safe: true` or the reason that applies. It is never called, not even through another tool: a released tool that calls one that is not released gets the dry-run value. Mark a tool `safe: true` only when it works on test data.

When no tool can run, the command exits with code 2 and prints `No tool can run: mark tools safe for test data.`

## Register tools when the module is imported

Gazua finds your tools by importing the module of `entrypoint` in an isolated process, with every tool in dry-run. It never calls the entrypoint in tools mode. Tools must therefore be registered at module level of the test module:

```python
# tests/agent_entry.py
import gazua
from myapp.tools import get_order, refund

TOOLS = gazua.wrap({"get_order": get_order, "refund": refund})


def entrypoint(message: str) -> str:
    return build_agent(TOOLS).run(message)
```

If tools are wrapped only inside the entrypoint, nothing is registered, and Gazua says so. Keep `gazua.wrap` in the test module so production code imports nothing from Gazua. Importing the module is not a sandbox: it must not call a provider or do real work outside the wrapped tools.

## HTTP targets

Tools mode needs direct access to the tools. An `entrypoint` that is a URL is refused before any request with `--tools needs direct tool access; use --agent for HTTP targets.` and exit code 2.

## Output

Before the first attack, Gazua prints the tools under test, the tools skipped with their reasons, the number of combinations to run and not runnable, the run limit and the concurrency. A counter follows; it never shows attack text or tool output.

The summary is the table by damage from [the verdict guide](verdicts.md), then each finding with its tool, the location of its proof, the proof conditions and a command that runs the mold again:

```text
High: Records of another user. get_order returned victim record #0 when called by the attacker. Gated.
  Mold: idor-01. Proof: executions/GAZUA-exec-0001/calls.redacted.jsonl, call 1. Conditions: fixture_specific.
  Reproduce: gazua run --tools --config gazua.yaml --mold idor-01
```

Fixtures appear by index and canaries by number. Tool returns, record ids and canary values are never printed. The reproduction command is quoted for your shell; a path that cannot be quoted safely gets an instruction instead of a command.

A resisted attack in tools mode means this version of your code returned nothing that proves the effect for that combination. It says nothing about a model, and one run is not a general guarantee.

## Exit codes

| Code | When |
|---|---|
| 0 | No finding at a gated severity and no operational error |
| 1 | At least one finding at a gated severity (`gate.fail_on`) |
| 2 | Invalid configuration, catalog or options; no tool can run; HTTP target; or an operational error such as a crash, a timeout, a failed reset, an unexpected tool call ceiling or an interruption |

Code 2 wins over code 1: a run with a finding and an operational error exits with 2, and the finding is still reported. Reaching `max_runs` or `max_cost` is not an error; what was left is reported as not tested. Reaching the tool call ceiling is expected for `repeat_sensitive_call`, and the verdict decides.

Every run also writes `.gazua/report.html`, `.gazua/report.md` and `.gazua/run.json`, with each finding's proof, reproduction command and fix. Masking, `--no-redact`, regeneration with `gazua report --from` and `gazua clean` are described in [the reports guide](reports.md).

## Limits and evidence

Limits, `target.reset`, process isolation and evidence follow [the execution guide](execution.md). With `target.reset`, attacks run one at a time. Tool returns are kept privately only until the verdict reads them, then deleted; the run folder under `.gazua/runs/` keeps the redacted call log of each attempt.
