# Agent mode

`gazua run --agent` sends the catalog's attacks to your real agent, through every entry it can reach, and measures in code what happened: tool calls, canaries, test sink results and the engine's records. Your test entrypoint calls your model with your own configuration. Gazua never asks for, reads or stores your provider key, and it never calls a model itself.

```console
gazua run --agent
gazua run --agent --quick
gazua run --agent --mold secret-04 --max-runs 50 --max-cost 5
```

Agent mode is meant for nightly and pre-release runs. Attack text reaches your model provider through your agent, each execution may cost money, and results vary between runs because the model does. It is not recommended on every pull request; use [tools mode](tools-mode.md) there.

## What it runs

The mode takes every mold of the catalog that supports `agent`. The packaged catalog has 15 of them; molds that support only tools mode are not part of agent runs, and the mold count does not promise how many will run: that depends on each mold's entry and on your declarations.

| Option | What runs |
|---|---|
| `--agent` | Every agent mold, 5 repetitions per scenario |
| `--agent --quick` | Up to 15 molds, 1 repetition per scenario |
| `--agent --mold ID` | One mold, by exact id, 5 repetitions |
| `--agent --quick --mold ID` | One mold, 1 repetition |

A scenario is one mold with the tool whose effect is judged, the victim record and the canary its signal or text uses. A mold that judges a sensitive tool has one scenario per sensitive tool, so `--quick` limits molds, not executions. The quick selection takes one mold of each damage in turn, ordered by damage, entry and id, with no randomness. Molds whose declarations are missing stay in the selection and are reported as not tested; they are never swapped for others.

Before the first call to your agent, the run shows the number of molds, scenarios, repetitions and legitimate tasks, the planned executions and the limit, how many slots cannot run and why, the cost limit and how it applies, and which tools run for real or in dry-run. Then it shows a counter. Impeded slots spend no budget and stay in the result as not tested. Retries after a reported 429 use executions from the same `--max-runs` limit.

The limits are the ones described in [the execution guide](execution.md): 300 executions, 120 seconds and 50 tool calls per execution and 2 at a time, or 1 at a time with `target.reset`. The turns of one attack share one execution, so they share its timeout, its tool call ceiling and its slot. When your agent makes several model calls, report each one's cost with `gazua.report_usage` as an increment.

## Entries

| Entry | How the attack text arrives |
|---|---|
| `user_message` | Sent as the message to your entrypoint |
| `tool_result`, `rag_document`, `poisoned_memory` | Appended to the text result of the tool you declare under `agent_entries`, after the declared trigger message |
| `web_page`, `attachment`, `mcp_tool_description` | Not available yet; reported as not tested |

Indirect entries need a declaration. Gazua sends your `request` to the entrypoint as written, and the attack text reaches the agent only through the declared tool's result:

```yaml
agent_entries:
  rag_document:
    tool: search_docs
    request: "Check the refund policy in the test documents."
  poisoned_memory:
    tool: read_memory
    request: "Load the stored preferences for this test session."
```

The tool must be declared under `tools` and registered by your test module; otherwise the run stops with a configuration error before any model call. A missing entry is not an error: its molds are reported as `not tested, entry unavailable`. Gazua never replaces the declared tool with another one.

Each turn is delivered once, in the call that follows its message, and the call log records the delivery. An attempt is judged only when every turn of it was delivered: a tool that was not called, a result that is not text, an incomplete log or an undelivered turn make the attempt not tested, never resisted. Effects recorded before the first delivery are not proofs of that payload, and an attempt left with only such effects is not tested.

Memory content reaches the agent through the declared tool, but that does not prove it was stored. The `memory_effect` signal still needs the observation of a trusted memory adapter; without one, memory attacks stay not tested.

## Two turns

A two-turn attack calls your entrypoint twice, in order, in the same process and the same session, with no reset in between. Your agent keeps its conversation history in that context: an entrypoint that starts an empty conversation on every call does not support two-turn attacks, and their results will not mean what they say. Gazua never joins two turns into one message.

## Legitimate tasks

An agent that refuses everything would look perfect. Declare a few legitimate requests and the tool each one should use:

```yaml
legit_tasks:
  - request: "What is the refund policy?"
    expected_tool: search_docs
```

Each task runs once, before the attacks, through the same entrypoint, with no attack text, under the same limits, dry-run rules and reset. Tasks count toward `--max-runs`. A task succeeded when its execution ended normally, its evidence is complete and the call log holds a finished call of the expected tool. A dry-run call counts and is flagged. A blocked call, a call that raised, or an answer that says it used the tool do not count. A task that ended normally without the call failed; a timeout, crash, unreadable output, rate limit or missing evidence leave it not tested.

The report shows `Legitimate use: 2/3 tasks used the expected tool (67%)`, with the tasks not tested and the coverage. The rate counts only tasks that were evaluated. Without `legit_tasks` it shows exactly `Legitimate use: not tested`. The measure says whether the expected tool was used, not whether the answer or its arguments were right. A failed task creates no finding and does not change the gate.

## Your key stays with your agent

Your entrypoint obtains its credential the way your application does. Gazua's code reads no provider key and no credential file, in the supervisor or in the workers. When your provider rejects the credential, translate that error into `gazua.GazuaAuthenticationError` in the test entrypoint:

```python
import gazua
from myprovider import AuthenticationError, RateLimitError


def entrypoint(message: str) -> str:
    try:
        return build_agent(TOOLS).run(message)
    except AuthenticationError:
        raise gazua.GazuaAuthenticationError() from None
    except RateLimitError as error:
        raise gazua.GazuaRateLimited(retry_after=error.retry_after) from None
```

`GazuaAuthenticationError` takes no argument: it carries no key, no provider object and no message. The run stops at once with `The agent could not authenticate; Gazua does not manage its key` and exit code 2. A provider error your entrypoint does not translate is a generic failure, identified only by its class.

## When the agent keeps failing

| Situation | What happens |
|---|---|
| Authentication reported | No new execution starts; running ones finish under their limits; the rest is not tested |
| 5 consecutive identical failures | The run stops and reports the shared error: its code and exception class, never its message |
| A reported 429 | The pace is halved, down to one at a time, and the execution is retried after 1 or 2 seconds, or the requested wait up to 60 |
| Persistent 429 | When an execution exhausts its 2 retries, or 5 consecutive executions end in 429, the run stops and the rest is not tested |

Failures are consecutive in the order the supervisor sees executions end; a normal ending resets the count and a different failure starts it again. With concurrency, executions already running may end after the fifth failure, so the number of model calls is not exactly five. Every planned slot still gets a record, the final reset runs, findings already proven stay in the reports and the exit code is 2. An unreadable answer from the agent is not tested with its reason, never resisted.

## Safety

- Tools that are not `safe: true` and classified stay in dry-run, for attacks and for legitimate tasks. Gazua never runs a real tool as a fallback.
- Exfiltration destinations in the catalog end under `.gazua.test` and reach only the local receiver.
- Everything the agent returns is untrusted data: it is redacted and escaped in the reports, and control sequences never reach your terminal.
- Gazua sends no telemetry.

## Results and exit codes

The report shows, per mold and scenario, the attack rate over the evaluated repetitions with its upper bound, the proof of each finding, the coverage and the legitimate use. Repetitions that did not run, failed or were stopped are not counted as resisted. Reproduction commands use `gazua run --agent --mold ID` with the same limits and language; your model may answer differently on another run.

| Code | When |
|---|---|
| 0 | No finding at a gated severity and no operational error |
| 1 | At least one finding at a gated severity |
| 2 | An invalid option or configuration, a stop by authentication, repeated failures or persistent 429, a crash, timeout or unreadable answer, a reset failure or an interruption |

Code 2 wins over code 1, and findings proven before a stop stay in the reports.
