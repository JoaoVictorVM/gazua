# Issue export

`gazua issues` turns the findings of a saved run into Markdown files, one per finding, ready to copy into a backlog. It runs offline: it reads a local `run.json`, never imports the target, never reads `gazua.yaml`, starts no process and opens no connection. It never opens an issue on GitHub, GitLab, Jira or any other service; you copy or upload the files yourself.

```console
gazua run --tools
gazua issues
```

```text
Wrote 2 issue files to .gazua/issues/GAZUA-run-20260101000000-abc123/.
Copy them into your backlog by hand; Gazua never opens issues on any service.
```

## What it writes

The files go to `.gazua/issues/<run-id>/`, one per finding, named `<finding-id>.md`, plus a `manifest.json` that marks the set as complete and Gazua's own. Every element of the run's findings is exported, including findings already known in the baseline and findings that do not fail the build. Resisted, conditional, not applicable and not tested scenarios never become issues. A finding that groups several scenarios stays one issue, and each scenario keeps its own rate and upper bound; samples are never added together.

Each issue is self-contained and holds:

- a title made of the severity and the damage, never the attack text;
- the full finding id, the run id, the mode, the severity and whether the finding is gated, and its baseline status when the run read a baseline;
- the proof in short: the typed conditions of explorability, each scenario's rate and upper bound, and the ids and sources of the proofs;
- the fix guide entry of its damage, with its three categories and the reference `fix-<damage>` (see [the fix guide](fix-guide.md));
- the confirmation command, `gazua verify <finding-id> --mode tools` or `--mode agent`, for POSIX shells, PowerShell and cmd.exe;
- the acceptance criteria as unchecked boxes;
- the limits of the interpretation.

Exporting meets none of the criteria and runs nothing: the command in the issue is text. If the finding is not in the baseline yet, the issue says to review the run and accept it with `gazua baseline --from <run.json>` before `gazua verify`. A normal run with 0/5 does not close a finding.

## Privacy

By default an issue carries no attack text, payload, proof excerpt, native locator, tool argument or return, conversation, fixture or reproduction argument. It says whether a reproduction command is available in the local report instead of copying it. Mold and tool names, which come from the configuration or the target, are masked again for the export, with no exception for declared test data, and escaped so they cannot add Markdown, links or HTML.

`--include-attack` adds, for each scenario of the finding, its attack description and payload, in literal blocks marked as untrusted. They stay masked: the option never turns masking off and never recovers a value that was masked in `run.json`. Masking recognizes known formats of secrets and personal data only; a value with no recognizable shape may not be detected, so review the files before sharing them.

A run captured with `--no-redact` is refused (exit code 2). Run `gazua run` again without `--no-redact` to export its findings. There is no `--no-redact` for issues.

## Options

| Option | Default | Effect |
|---|---|---|
| `--from PATH` | `.gazua/run.json` | The local run document to read; schema versions 1, 2 and 3 are accepted, at most 64 MiB and 64 levels deep |
| `--include-attack` | off | Also copy each scenario's attack text and payload, still masked |
| `--overwrite` | off | Replace this run's previous export, even if its files were edited |

There is no option to choose another destination; copy the files from `.gazua/issues/<run-id>/` to wherever your backlog needs them.

## Running it again

Exporting the same run again with the same options and the same Gazua writes nothing and says the files are already up to date. If the content or the options changed, or a file in the folder was edited, the command stops (exit code 2) and asks for `--overwrite`, so manual edits are never lost silently. Even with `--overwrite`, a folder without a valid manifest or with files Gazua did not write is left as it is, and exports of other runs are never touched.

The set is published as a recoverable transaction under the project's lock: if the command is interrupted, the previous set stays, or is restored by the next Gazua command. A partial set is never announced. Links, junctions and other reparse points under `.gazua/issues/` are refused and never followed.

Exports are not runs: the retention of the last 20 runs never removes them, so an expired report does not take its backlog files with it. `gazua clean` removes the managed exports and keeps anything else under `.gazua/issues/`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Export written, already up to date, or the run has no finding (nothing is created) |
| 2 | The `run.json` is missing, corrupt, too large or of an unknown schema version; it was captured with `--no-redact`; the destination conflicts, is not managed or is a link; writing failed; or another Gazua command holds the lock |
| 130 | Interrupted with Ctrl+C; nothing partial was published |

The exit code of the run itself is never inherited: a run that failed the build on a gated finding still exports with 0.
