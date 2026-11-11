# Running attacks safely

This page explains how Gazua runs each attack against your agent: the limits that stop a runaway execution, what happens to cost and rate limits, how `target.reset` is used, where exfiltration attempts end up and what is recorded. The engine described here is what the run modes use. `gazua run --tools` uses it today, as described in [the tools mode guide](tools-mode.md); agent mode reuses it when it ships.

## Before the first attack

Gazua shows the size of the run before anything is executed:

```text
Running 225 executions: 45 molds x 5 repetitions. Limit 300. 3 real tools, 9 in dry-run.
Concurrency 2.
Retries after a reported 429: up to 2 per execution, counted in the limit of 300.
```

The tool summary comes from importing your entrypoint module in an isolated process with every tool in dry-run. No attack runs during that check, and if your module cannot be imported, the run stops there. A live counter follows, with executions started, active, finished and not run. It never shows attack text.

## One process per attack

Each attempt runs in its own Python process, started with the interpreter that runs Gazua and without a shell. The session is in place before your code is imported. When an attempt hangs, crashes or reaches a limit, Gazua kills that process and every process it started, records why and moves on to the next attempt.

- On Linux the attempt leads its own process group, and the group is killed.
- On Windows the attempt runs inside a Job Object that kills all its processes when it closes.
- If Gazua cannot put the attempt under this supervision, it does not start your code at all.

A process is isolation from failures, not a sandbox for hostile code. Your agent runs with your permissions, your network and your environment, exactly as it would in your own tests.

Output that your agent prints is captured, at most 64 KiB per stream, redacted and stored with the attempt. It is never printed to your terminal, and Gazua never records tracebacks or exception messages from your code, only the exception class.

## Limits

| Limit | Default | What happens when it is reached |
|---|---|---|
| `timeout` | 120 seconds | The attempt and its processes are killed and recorded as `timed_out`. The time includes importing your module, the reset before the attack and the entrypoint |
| `max_tool_calls` | 50 | The 50th call is admitted and reported first; any later call raises `GazuaBlockedError` before it runs, even if your agent catches the error and keeps trying. The attempt is killed and recorded as `killed_at_ceiling` |
| `max_runs` | 300 | No attempt starts beyond it, retries included. Everything left is recorded as `skipped_by_limit` and is not tested, never passed |
| `concurrency` | 2 | At most this many attempts run at once. With `target.reset` declared, attempts run one at a time |
| `max_cost` | none | See below |

Override them in `gazua.yaml` under `limits`, or with the flags of the run modes. With 225 executions planned and a limit of 100, exactly 100 start and 125 are reported as not tested.

The tool call limit counts calls that go through `gazua.wrap` or `@gazua.tool` in the attempt's process. The call that reaches the limit may finish, so its outcome can be unknown. Tools your agent runs in other processes, or calls without the wrapper, are not counted.

## Cost

Gazua never sees your model calls, so it cannot measure what a run costs on its own. `max_cost` works only with one of these sources:

- **`cost_per_run`** in `gazua.yaml`: an estimate in USD reserved before each attempt starts, retries included, and never given back. When the next reservation would pass `max_cost`, nothing else starts. This is the only source that is checked before spending.
- **Reported usage**: your entrypoint calls `gazua.report_usage(cost_usd=...)` with the cost of each model call. Each call adds an increment; never pass a running total. When the reported total reaches `max_cost`, Gazua stops starting attempts and kills the active ones, but money already spent by calls in flight cannot be stopped, so the run may end slightly above the limit.

```python
import gazua


def entrypoint(message: str) -> str:
    reply = client.messages.create(...)
    gazua.report_usage(cost_usd=price_of(reply.usage))
    return reply.content[0].text
```

Outside a run, `gazua.report_usage` does nothing and returns `False`. Gazua never converts tokens into dollars, never calls a provider and never reads your API keys.

When `max_cost` is set and neither source exists, Gazua prints before the first attack:

```text
Warning: max_cost does not apply without reported usage or cost_per_run.
```

The same warning appears when usage was promised but an attempt reported none, and the summary marks the cost coverage as incomplete. Missing usage is never counted as zero. `max_runs` applies in every case.

## Rate limits

When your model provider answers 429, raise `gazua.GazuaRateLimited` from your entrypoint, with the wait the provider asked for when it gave one:

```python
except provider.RateLimitError as error:
    raise gazua.GazuaRateLimited(retry_after=error.retry_after) from None
```

Gazua then halves the number of attempts it runs at once, never below one, waits 1 second and then 2 seconds (or the `retry_after` you passed, up to 60 seconds) and tries again, at most twice per execution. Each retry is a new attempt that counts in `max_runs`. A 429 is recognized only through this exception, never by reading error messages.

A retry repeats the attack. Gazua retries only when the failed attempt made no real tool call, or when `target.reset` restores the state before the new attempt. Otherwise the attempt is recorded as `rate_limited` with the reason `retry_unsafe`.

## `target.reset`

When `gazua.yaml` declares `target.reset`, Gazua calls it inside each attempt's process before the attack, and once more in a separate process after the last attempt, also after Ctrl+C. Each attempt already starts with fresh memory, so the hook is for state outside the process: a test database, files, a mailbox. Test data that Gazua creates carries the prefix `GAZUA-`; keep the data your hook restores synthetic too.

If the reset fails or hangs, the state can no longer be trusted. Gazua stops starting attacks, records the attempt and every pending one as `reset_failed`, and still tries the final reset. The final reset has the same timeout as an attack; if it hangs, it is killed and the summary reports the failure.

## Exfiltration attempts

Some attacks try to make the agent send data to an external address. In the catalog, those addresses are always under `.gazua.test`, a name that never resolves on the internet. To capture them, the tool that would send the data calls `gazua.send_to_receiver` in your test entrypoint instead of making the request:

```python
import gazua


def http_post(url: str, body: str) -> str:
    gazua.send_to_receiver(url, method="POST", body=body)
    return "sent"
```

During a run, Gazua starts a receiver on `127.0.0.1` and the request goes there over plain HTTP with a token for that attempt. The `.gazua.test` URL, `https` included, is only a label: nothing is resolved, no external connection is opened, no certificate is checked or disabled, and proxy variables are ignored. Only `Content-Type` is kept from the headers.

`gazua.send_to_receiver` raises `GazuaReceiverError` without connecting anywhere when the URL is not under `.gazua.test`, when there is no run in progress or when the run has no receiver. Unlike `gazua.wrap`, it never sends a real request outside a run.

The receiver accepts at most 100 requests per attempt, 1 MiB each, and only from the attempt that owns the token. Anything beyond that is recorded as incomplete coverage, never dropped in silence. An attack that needs this capture and has no transport declared is reported as not tested.

Gazua does not intercept HTTP libraries. A request your agent makes without `gazua.send_to_receiver` goes to the network as usual, and the model calls of your agent use the network normally.

## Ctrl+C

The first Ctrl+C stops new attempts, kills the active ones, records the rest as not tested with the reason `interrupted`, runs the final reset and writes the partial summary. A second Ctrl+C during the final reset aborts it, and the summary records that the reset did not finish.

## What is recorded

Everything a run writes stays under `.gazua/runs/<run-id>/engine/` in your project:

- `summary.json`: limits, counts by status, retries, cost source and coverage, the final reset and operational errors. It is rewritten after each attempt, so an interrupted run still has one.
- `executions/<execution-id>/execution.json`: one record per attempt and per execution that never started.
- Redacted copies of the call log, receiver hits, response and captured output of each attempt.

| Status | Meaning |
|---|---|
| `completed` | The attempt finished. It says nothing about whether the agent resisted |
| `timed_out` | Killed at `timeout` |
| `killed_at_ceiling` | Killed after reaching `max_tool_calls` |
| `skipped_by_limit` | Not started because of `max_runs` or `max_cost` |
| `crashed` | The process died or the entrypoint failed |
| `reset_failed` | The reset failed, so the attack did not run or its state cannot be trusted |
| `rate_limited` | The provider answered 429 and the attempt was not retried, or was retried |
| `cancelled` | Killed by Ctrl+C or by the cost limit |
| `not_tested` | Not started, for example after Ctrl+C or without a receiver |

Records say when evidence may be incomplete, for example after a kill or a cut log line. Incomplete evidence is never read as proof that an attack had no effect. How records and evidence become one state per attack is explained in [the verdict guide](verdicts.md).

Raw evidence, which can contain canaries and test data, stays in a private folder of the run, readable only by your user, while the verdicts read it, and is deleted afterwards. This includes the tool returns the wrapper keeps for verdicts, which are never copied to the redacted evidence. What persists is redacted: declared canaries, key-shaped text and email addresses are replaced. If Gazua stops abruptly, the next run under the same project removes the leftover private folder.

The formats are public JSON Schemas packaged with Gazua: [`execution-v1.schema.json`](../src/gazua/schemas/execution-v1.schema.json), [`receiver-hit-v1.schema.json`](../src/gazua/schemas/receiver-hit-v1.schema.json) and the session of a supervised attempt, [`session-v2.schema.json`](../src/gazua/schemas/session-v2.schema.json).

## When something goes wrong

| What happened | What Gazua does |
|---|---|
| An attack hangs | Kills it and its processes at `timeout`, records `timed_out`, continues |
| The agent crashes | Records the exit status and redacted output, continues |
| A runaway tool loop | Refuses calls after `max_tool_calls`, kills the attempt, records `killed_at_ceiling` |
| `max_runs` is reached | Records the rest as `skipped_by_limit`, finishes the summary |
| `target.reset` fails | Stops the attacks, records them as `reset_failed`, still tries the final reset |
| Reported cost reaches `max_cost` | Kills active attempts, starts no more and says the limit may be passed by calls in flight |
| No capture for an exfiltration attack | Records it as `not_tested` before it starts |
| Processes cannot be killed or the final reset fails | Starts nothing else and reports an operational error in the summary |
