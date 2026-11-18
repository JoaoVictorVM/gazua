# Baseline and verification

A baseline records which findings your team already knows about, so the build fails only on new ones. `gazua verify` checks a fix by repeating the finding's attack 20 times per scenario; only then can a finding close.

```console
gazua run --tools
gazua baseline
gazua run --tools
gazua verify idor-01 --mode tools
```

## Accepting findings with `gazua baseline`

`gazua baseline` reads a saved `run.json`, by default `.gazua/run.json`, and writes `gazua-baseline.json` at the project root, next to `gazua.yaml`. It runs nothing: no target is imported and no model is called. Pass `--from` to accept another saved run, such as `.gazua/runs/<run-id>/run.json`, and `--output` to choose another file inside the project. The file cannot be under `.gazua/`, be a link or be the configuration file.

A run that was interrupted or had an operational error is refused (`baseline_source_incomplete`). A run with exit code 1 is fine: accepting its findings is the point. When some scenarios were not tested, for example because a limit closed admission, the command says so: the baseline does not certify scenarios that never ran.

Every finding of the run is accepted as `open`, whatever its severity. Each entry covers every scenario of its mode, mold and tool in that run, not only the ones that succeeded. Accepting is a merge, never a replacement:

- entries the run does not show are kept, open or closed; nothing is closed by absence;
- a finding seen again keeps its entry and its coverage only grows;
- a finding that was closed and is accepted again is reopened and loses its verification receipt;
- a merge that changes nothing writes nothing, so the file keeps its bytes and its revision.

The command prints how many findings were accepted, preserved and reopened. Commit `gazua-baseline.json` with your code; `gazua clean` and the retention of the last 20 runs never touch it.

## What the file holds

```json
{
  "schema_version": 1,
  "gazua_version": "0.1.0.dev0",
  "revision": 1,
  "entries": [
    {
      "id": "finding-<sha256>",
      "mode": "tools",
      "status": "open",
      "scenarios": [{ "scenario_digest": "<sha256>", "language": "en" }],
      "verification": null
    }
  ]
}
```

Only opaque identifiers: the finding id, its mode and state, and each covered scenario as the SHA-256 of its attack key with the language it ran in. No attack text, payload, conversation, fixture, canary, tool argument, evidence path, reproduction command or free text is stored. A closed entry carries a receipt: the verification's run id, its date, `"repetitions": 20` and the same scenarios. The receipt guards against accidental closure; it is not a signature, and anyone who can edit the repository can edit the file.

The JSON Schema is [`src/gazua/schemas/baseline-v1.schema.json`](../src/gazua/schemas/baseline-v1.schema.json). Compatibility follows `schema_version`, not the Gazua version that wrote the file: a baseline written by another Gazua with the same schema version is read as it is. An unknown schema version is refused with `baseline_version_unsupported`; install a Gazua that reads it, or follow the migration documented for that version when one exists.

## Comparing a run

`gazua run --tools` and `gazua run --agent` use `gazua-baseline.json` automatically when it exists. `--baseline PATH` uses another file, which must exist; `--no-baseline` ignores any baseline. With a baseline the run says, for example, `2 known findings, 0 new`, and:

| Finding in this run | Shown as | Fails the build |
|---|---|---|
| Not in the baseline | new | when gated by `gate.fail_on` |
| Open in the baseline | known | never |
| Closed in the baseline | new, closed before and found again | when gated |

Exit codes: 0 when no new gated finding appeared, 1 for a new gated finding, 2 for any operational, configuration, report or baseline error. A known finding never hides an error. The gate is `gate.fail_on` in `gazua.yaml`, high and critical by default; an empty list means no severity fails. Without a baseline, runs behave as before.

Known findings keep their proofs, rates and native gate in the report; only the effective decision changes. Entries the run did not observe are listed apart as history this run did not confirm. That a finding did not appear in a run, even with 0/5 repetitions, never closes it, and a normal run never writes the baseline. In CI, the baseline is only read: new findings are never accepted automatically.

A missing default file means no baseline. A file that exists but cannot be read is an error with exit code 2, never an empty baseline, because an empty baseline would make every known finding fail and a wrong one could hide new findings:

| Code | Meaning |
|---|---|
| `baseline_missing` | `--baseline` or `gazua verify` named a file that does not exist |
| `baseline_invalid` | Not valid JSON, duplicate keys, NaN or Infinity, extra fields or broken rules |
| `baseline_version_unsupported` | Another schema version |
| `baseline_limit_exceeded` | More than 8 MiB, deeper than 16 levels, more than 10,000 entries or 100,000 scenarios |
| `baseline_path_invalid` | A link, a folder, a path outside the project, under `.gazua/` or the configuration file |
| `baseline_conflict` | The file changed while the command ran; nothing was overwritten |
| `baseline_write_failed` | The file could not be written; the previous file was kept |

Errors name the code and the field, never the rejected content.

The report keeps a snapshot of the comparison: the baseline's revision and digest and the state of each finding. `gazua report --from` rebuilds it from that snapshot alone, even if the baseline changed or was removed. `run.json` is written with `schema_version` 4, which adds the target adapter and MCP provenance; documents with schema version 3 keep their fix guide, documents with schema version 2 keep their comparison and verification when read, and documents with schema version 1 are still read and rebuilt, with no comparison. Every schema is published in `src/gazua/schemas/`.

## Verifying a fix with `gazua verify`

```console
gazua verify idor-01 --mode tools
gazua verify finding-<sha256>
```

The argument is a full finding id or the exact mold id of one accepted finding. When a mold matches several accepted findings, for example the same mold on two tools, the command lists their ids and asks for `--mode` or the full id. An id of another target, a removed mold or a finding not in the baseline is refused.

Verification runs the current code, configuration and catalog, through the same engine, limits, reset, dry-run, receiver and evidence capture as a run. It plans 20 repetitions of every scenario the baseline covers for that finding, plus the scenarios the current configuration builds for the same mode, mold and tool, in each language the baseline recorded. Each scenario and language keeps its own sample: 20 per scenario, never 20 split among them. Retries of an execution belong to the same repetition, and legitimate tasks are not part of a verification. Before the first attempt it shows the number of scenarios and executions and the limits; when `max_runs` or the known cost cannot fit every repetition it refuses (`verification_insufficient_budget`) and runs nothing. Limits are never raised for you; pass `--max-runs` and the other limit options explicitly.

| Result | State | Exit code |
|---|---|---|
| 0 successes in 20 conclusive repetitions of every scenario | closed | 0 |
| Any success in a complete verification | open, with the rate | 1 |
| Interrupted, incomplete, low fidelity, a failed reset or any operational error | unchanged | 2 |

Closure needs, for every scenario, 20 evaluated repetitions with no success, no unknown or not applicable repetition, complete coverage and no low fidelity evidence, with no operational error, a working final reset and no interruption. The upper bound of 0/20 at 95% confidence is about 13.9%, shown as `0/20, up to ~14%: closed`. With several scenarios each rate is shown on its own; they are not one sample of 40 and there is no joint 95% confidence. In tools mode the repetitions check the control in the tested context; they do not measure how a model resists.

The report with the decision is saved first; only then is the baseline replaced, atomically and only if it still has the content read at the start. The report says what the evidence allowed at that time, such as `0/20; closure eligible at verification time`; the command names the new state only after the file was written. If the second write fails, the evidence stays in the report and the baseline keeps its previous state. A success with an incomplete verification reopens the finding but still exits with 2. An interruption never changes the state, even after a success.

Accepted scenarios that can no longer be built, because a fixture, canary or tool changed or a channel is not available, stop the verification with `verification_coverage_changed`. Removing coverage never counts as a fix: restore it, or accept the new state explicitly.

## Limits of interpretation

A finding's id depends on the target entrypoint, mode, mold and tool, not on the model, its version, the fixture or the folder. A verification tests the current target and catalog; it does not rebuild the historical environment. Scenario digests detect a changed attack key, but they do not certify the catalog's text: editing a mold's text without changing its identity is not a byte-for-byte replay. A closed finding means 0/20 in the tested scenarios, not resistance outside the catalog, equivalence between models or a fix proven by removing a tool.
