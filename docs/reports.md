# Reports

Every `gazua run --tools` ends with three files in `.gazua/` of the project, next to `gazua.yaml`:

| File | What it is |
|---|---|
| `.gazua/run.json` | The run document. Reports are rebuilt from it alone. |
| `.gazua/report.html` | One self-contained page that opens offline, with filters by damage and state. |
| `.gazua/report.md` | The same content as portable Markdown. |

The terminal prints the summary by damage and state, each finding with its conditions, reproduction command and fix, and the paths of the files that were actually written. The exit code stays the one of the mode: 0 when nothing at a gated severity was found, 1 for a gated finding, 2 for an operational error, which wins over 1.

```console
gazua run --tools
gazua report --from .gazua/run.json
gazua clean
```

Nothing is uploaded and no browser is opened. Gazua sends no telemetry and never reads provider credentials.

## What a report shows

Every attack unit appears exactly once, in one of five states: finding, conditional risk (not verified), resisted, not applicable and not tested. Each section is present even when it is empty, and every not tested or not applicable item keeps its reason, for example `not tested, missing safe: true`. Rates and upper bounds are the verdict engine's, unchanged, and cover only the repetitions that were evaluated; a partial sample says so. A resisted attack is reported for this version only, never as a property of the agent.

Only verified results become findings. A finding carries:

- a stable id, `finding-` and the SHA-256 of the target entrypoint, mode, mold and tool, so the same problem keeps its id across runs, models, fixtures and folders;
- severity, damage and the attack, as fixed text that describes what was done;
- the proof: the native locator (execution, call sequence, hit, evidence reference and facts) and a treated excerpt of the evidence;
- the conditions of explorability, such as `fixture_specific` or `dry_run`;
- the reproduction command for POSIX shells, PowerShell and cmd.exe;
- a short fix and its reference, the damage name, anchored in the report as `fix-<damage>`.

Scenarios of the same mold and tool, such as two victim records, belong to one finding but keep their own rates; rates are never added. The finding's severity is the highest of its scenarios and its gate is set when any of them is gated. Low findings of the same damage and tool are grouped on screen only; each keeps its id, proofs and counts.

A conditional risk stays outside the findings: it is an unhandled output that could not be verified, for example because no `output_sink` is declared.

## Reproduction

The command runs every scenario of the mold again, from the project root, with the same configuration and target code:

```console
gazua run --tools --config gazua.yaml --mold idor-01
```

Limit options that can change a result, such as `--max-tool-calls` or `--timeout`, are kept; `--concurrency` is not, and `--no-redact` is never added. Reproducing needs the same `gazua.yaml` and the same code of the target; the command does not replay a single scenario. When an argument has control characters, or masking changed it, no command is offered and the report says why.

## Masking

Evidence that reaches `run.json`, the reports and the redacted files under `.gazua/runs/<run-id>/engine/` is masked before it is written:

- key-shaped secrets (OpenAI, Stripe, AWS, GitHub, GitLab, Slack, Google, npm and PyPI tokens) and whole private key blocks;
- values of fields named like `password`, `passwd`, `secret`, `token`, `authorization`, `api_key`, `cookie` or `set_cookie`;
- whole values of full name, address and date of birth fields;
- email addresses, Brazilian phone numbers with area code and international numbers that start with `+`;
- CPF and CNPJ, with or without punctuation, and card numbers of 13 to 19 digits with a valid Luhn check.

Declared test data stays visible: fixture identities, fixture record ids and canaries from `gazua.yaml`. They are exempt only as whole values; text that merely contains a canary, such as a larger token, is masked in full. The exemptions come from the validated configuration, never from what the target returns.

Masking is based on formats and field names. It does not discover a random secret with no recognizable shape, and Gazua never lists the environment to look for one. When treating a field fails, the whole field becomes `[redacted-field]`, the report records `redaction_failed` with the field's name, never its value, and the exit code is 2. The verdict itself is not changed.

Each excerpt keeps at most 16 KiB and a run keeps at most 8 MiB of excerpts, proofs first. Truncation and missing excerpts are marked; a missing excerpt never turns into a complete proof, and the native locator stays.

### `--no-redact`

```console
gazua run --tools --no-redact
```

Turns masking off for the evidence captured by this local run only. Escaping, control sequence removal and size limits still apply. The terminal and both reports show a warning. It is refused, before the target is imported, when any of `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `TF_BUILD`, `JENKINS_URL`, `BUILD_BUILDID` or `CIRCLECI` is set to a value other than empty, `0` or `false`. This check is a safety net, not an access control: whoever controls the process can change its environment.

Data masked by an earlier run cannot be recovered: `--no-redact` never brings back what a placeholder replaced.

## Untrusted text

Attack, target and model text are untrusted everywhere. The HTML autoescapes every value, shows attack text only as literal blocks and loads nothing: its Content Security Policy allows only the packaged style and script, by hash, and blocks network, forms, images, objects and base URLs. Filters work without any request; without JavaScript every item stays visible. Markdown escapes inline values and fences literal blocks longer than any backtick run inside them; it emits no link that the target provided. The terminal drops whole escape sequences (CSI, OSC including hyperlinks and clipboard writes, DCS and the others) and every control character except line breaks and tabs.

## Regenerating

```console
gazua report --from .gazua/run.json
gazua report --from /path/to/an/old/run.json
```

`gazua report` reads a local `run.json` (at most 64 MiB and 64 levels deep), validates it and rewrites `report.html` and `report.md` in `.gazua/` of the current directory, with a copy of the source as `.gazua/run.json`. It does not import the target, read `gazua.yaml`, open the evidence files the document mentions or run any attack, and it does not create a run, change the history or the retention. The same document and the same Gazua version give the same reports. A document captured with `--no-redact` needs `--no-redact` again to be rebuilt, which is refused in CI. An unknown `schema_version` exits with 2 and asks for a migration.

`gazua run` writes under the folder of the configuration; `gazua report` and `gazua clean` work on the current directory.

## Storage, retention and cleaning

| Path | Content |
|---|---|
| `.gazua/runs/<run-id>/engine/` | Execution records and redacted evidence of the run |
| `.gazua/runs/<run-id>/run.json`, `report.html`, `report.md` | The run's own copies |
| `.gazua/runs/<run-id>/manifest.json` | Written last; marks the folder as a finished Gazua run |
| `.gazua/run.json`, `report.html`, `report.md` | The latest set |
| `.gazua/.lifecycle.lock` | Lock held while a command uses `.gazua/` |

The latest set is replaced as a recoverable transaction. If a publication is interrupted, the next command restores the previous set before reading or changing it. When the reports cannot be written, the summary in the terminal is still complete, the previous latest set is kept and the exit code is 2.

After each new run, Gazua keeps the last 20 finished runs, ordered by date, and removes the oldest one with its engine folder. Only folders with a valid manifest count; unknown folders are never removed.

`gazua clean` removes every finished run, the latest set and Gazua's temporary files. It keeps `.gazua/` itself, the lock file and anything it does not recognize, never follows links and refuses to run while another Gazua command holds the lock. Running it again removes nothing. A run folder from an older Gazua without a manifest is kept unless the engine's private marker identifies it as an interrupted run.

A command that changes `.gazua/` takes the lock before the target is imported; a second command in the same project exits with 2 instead of waiting.

## Errors

| Condition | What happens | Exit |
|---|---|---|
| `.gazua/` cannot be written before the run | No attack runs; every planned attack is not tested with `report storage unavailable`; full summary | 2 |
| A write fails during the run | No new attack starts; running ones and the final reset finish; partial results are printed in full | 2 |
| The reports cannot be written after the run | Summary printed; previous reports kept | 2 |
| Masking fails on a field | The field is hidden and flagged | 2 |
| `.gazua/` is not in the project's `.gitignore` | A warning on every run; the file is never edited | unchanged |
| Another command holds the lock | Nothing is removed or written | 2 |

Gazua checks the ignore rule with `git check-ignore` when Git is available. A rule only in `.git/info/exclude` or in a global excludes file does not count, because it does not travel with the project. Without Git, only the simple `.gazua/` line in the root `.gitignore` is recognized.

## For other tools

The run document follows `src/gazua/schemas/run-v1.schema.json`, `schema_version` 1. Its findings, scenarios, proof snapshots and fixed fix references are the contract later commands build on; they are available from `gazua.reports` without importing a target.
