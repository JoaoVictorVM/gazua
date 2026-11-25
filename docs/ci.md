# CI integration

Gazua runs in GitHub Actions as a composite Action. On each pull request it runs tools mode, keeps one updated comment with the result, uploads SARIF so findings appear in code scanning, and fails the job only on a new gated finding.

```text
Gazua security tests

1 new high finding, 2 known, 4 not tested
Gate: failed, a new gated finding.
```

## Safe workflow

Copy [`docs/examples/gazua-github-actions.yml`](examples/gazua-github-actions.yml) to `.github/workflows/gazua.yml`:

```yaml
name: gazua

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  gazua:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: JoaoVictorVM/gazua@<full-commit-sha> # the commit you reviewed
        with:
          mode: tools
          config: gazua.yaml
          github-token: ${{ github.token }}
```

Three rules keep this workflow safe:

- **`pull_request`, never `pull_request_target`.** `pull_request_target` runs with the base repository's token and secrets; combined with the pull request's code, a malicious `gazua.yaml` or target could steal them. The Action refuses it with exit code 2 before reading anything from the project.
- **Minimal permissions.** `contents: read` to check out, `pull-requests: write` for the comment and `security-events: write` for code scanning. Nothing else.
- **Pinned by full SHA.** Tags can be moved; a commit SHA cannot. Every action in the example, Gazua included, is pinned that way. Review the Gazua commit you pin.

The checkout keeps no credentials (`persist-credentials: false`), and the Action never adds another checkout.

## Inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `tools` | `tools` or `agent`. A pull request from a fork always runs `tools` |
| `config` | `gazua.yaml` | Configuration file, relative to the workspace |
| `mold` | empty | Run only this mold, by exact id |
| `baseline` | empty | Baseline file, relative to the workspace; empty keeps the default `gazua-baseline.json` detection |
| `comment` | `true` | Keep one updated comment on the pull request |
| `upload-sarif` | `true` | Upload the SARIF file to code scanning |
| `upload-evidence` | `false` | Upload this run's reports and redacted evidence as an artifact |
| `github-token` | empty | Used only by the comment step. Pass `${{ github.token }}` |
| `python-version` | `3.11` | Python of the Action's own environment |

Boolean inputs accept only `true` or `false`, in lowercase. There is no input for free arguments: limits, language, target and gates stay in `gazua.yaml`.

| Output | Meaning |
|---|---|
| `exit-code` | `0`, `1` or `2`, Gazua's effective result |
| `effective-mode` | The mode that actually ran |
| `run-json` | Path of `.gazua/run.json` |
| `sarif`, `comment`, `summary` | Paths under `.gazua/ci/`, when valid |
| `new-findings`, `known-findings`, `not-tested` | Counts of the run |

All paths are relative to the workspace. When `config` is in a subfolder, `.gazua/` is created next to it, as with `gazua run`.

## What runs

1. The event is checked first: its name, its payload, the repository and, on a pull request, where the pull request came from. Unsupported events and incoherent payloads stop the Action with exit code 2.
2. The Action installs Gazua from its own lock file into an isolated environment, with no dependency cache.
3. `gazua run --tools` (or `--agent`, see below) runs with the job's environment minus the Action's own credentials: `GITHUB_TOKEN`, `GH_TOKEN`, the Actions runtime and OIDC tokens and every Action input are removed. The target never receives the token used for the comment.
4. The run's exit code is kept, then the CI files are built from `.gazua/run.json`.
5. The comment step, the only one that receives the token, updates the comment. SARIF and, when asked, evidence are uploaded.
6. The last step applies the gate.

The target runs in the Action's environment, which has Gazua and its own dependencies only. A target that imports other packages cannot be loaded there; run `gazua run --tools` and `gazua sarif` in your own job instead, after installing your project, or use [the pytest plugin](pytest.md).

## Forks

A pull request from a fork is detected by comparing `pull_request.head.repo.full_name` with the repository. A payload without these fields is an error, never a trusted pull request.

On a fork, only tools mode runs, with no secrets. If the workflow asks for `mode: agent`, the Action runs tools mode instead and says so in the log. GitHub already withholds secrets from fork pull requests and reduces the workflow token; the Action adds that its token never reaches the target's process.

Agent mode calls your real agent, its model and its key. Use it only on events you trust, such as `push` to your main branch, `workflow_dispatch` or `schedule`, with the keys configured in your own workflow. The Action never asks for or stores provider keys.

## The comment

The comment starts with the marker `<!-- gazua-ci-comment:v1 -->` and shows:

- the summary line, for example `1 new high finding, 2 known, 4 not tested`;
- whether the gate passed;
- a table of the observed findings by severity and id: severity, damage, tool, status (`new`, `new, regression`, `known` or `no baseline`) and finding id;
- the local command that reproduces each finding;
- a note that passing is a floor, not a certificate;
- the paths of the local reports.

It never holds attack text, payloads, conversations, proofs, tool arguments or returns, canaries, fixtures, the target reference or error messages: review bots could follow them. Tool names and command tokens with any character outside a small safe set are left out, with a diagnostic code.

Only one comment is kept. The Action looks for comments written by the token's own identity that start with the marker; it updates the oldest one when its text changed, and removes newer copies it wrote. A comment by anyone else is never edited, even with the same marker. Over 60 KiB, the least severe findings are left out of the table and the comment says how many.

When the token cannot comment (a fork, or missing `pull-requests: write`), the job result does not change: the summary stays in the log and in the job summary.

## Code scanning

The SARIF file follows SARIF 2.1.0 and the Gazua profile `gazua-sarif-v1`. Each observed finding is one alert:

| SARIF | Value |
|---|---|
| `ruleId` | `gazua/<damage>`, one rule per damage |
| `level` | `error` for critical and high, `warning` for medium, `note` for low |
| `partialFingerprints["gazuaFindingId/v1"]` | The finding id, so changing text never duplicates an alert |
| `baselineState` | `new` or `unchanged` when the run had a baseline |
| location | The configuration file, with no line: Gazua does not know which line is at fault |

Not tested and not applicable scenarios are never alerts; they are counts and notifications in the run's invocation. The upload uses the category `gazua/tools` or `gazua/agent`.

Code scanning may be unavailable for the repository's plan or visibility. A failed upload is a warning: the job result still reflects the gate, and the file stays in `.gazua/ci/gazua.sarif`.

To produce the same file locally, offline:

```console
gazua sarif
gazua sarif --from .gazua/runs/<run-id>/run.json --output gazua.sarif --config-path app/gazua.yaml
```

`gazua sarif` reads every supported `run.json` version, never imports the target, reads the configuration or opens the network, and writes the file atomically. It exits 0 when the file was written, even when the run had findings, and 2 when the run is invalid, a path is refused, a limit (10,000 results or 32 MiB) is exceeded or the write fails. `--config-path` only sets the location shown in the alerts.

## Evidence

By default no evidence leaves the runner. With `upload-evidence: true`, the Action uploads an artifact named `gazua-evidence-<run-id>`, kept 7 days, with this run's latest reports and its history folder: `run.json`, `report.html`, `report.md`, the manifest and the redacted per-execution evidence. It never includes the configuration, the baseline, `.env` files, Git metadata, private engine files or anything unknown, and refuses links. The evidence is redacted, but masking only recognizes known formats; review what you upload.

A requested upload that does not happen fails the job with exit code 2.

## The gate

| Situation | Exit |
|---|---|
| No new gated finding | 0 |
| A new gated finding | 1 |
| A known finding (open in the baseline) | 0 |
| Operational error in the run, or no run produced | 2 |
| No permission to comment, or comment API error | unchanged |
| SARIF upload failed | unchanged |
| SARIF or comment could not be built locally | 2 |
| Evidence requested and not uploaded | 2 |
| `pull_request_target` or unsupported event | 2 |

## Files

The CI files live in `.gazua/ci/`, next to the reports:

| File | Content |
|---|---|
| `summary.json` | The minimal projection, schema `ci-summary-v1` |
| `comment.json` | The comment's data, schema `pr-comment-v1` |
| `comment.md` | The comment's Markdown |
| `gazua.sarif` | SARIF, profile `gazua-sarif-v1` |
| `evidence/<run-id>/` | Staged evidence, only with `upload-evidence: true` |

Each file is written to a temporary name, checked and then moved into place. `gazua clean` removes `.gazua/ci/` only when its marker is valid and it holds nothing unknown; the folder is never counted as a run.

## Versions

`ci-summary-v1`, `pr-comment-v1` and `gazua-sarif-v1` are the first published versions; their schemas are in `src/gazua/schemas/`. A new field never enters a v1 document: an incompatible change gets a new version. The SARIF file keeps `version` 2.1.0 and states its profile in `runs[].properties.gazuaProfile`. The Action declares the contract revision it needs and stops if the installed Gazua does not know it. These formats are not frozen yet; a later release will set their long-term compatibility rules.

## Errors

| Code | Meaning |
|---|---|
| `ci_pull_request_target_refused` | The workflow uses `pull_request_target`; use the safe example |
| `ci_event_refused` | The event is not `pull_request`, `push`, `workflow_dispatch` or `schedule` |
| `ci_event_invalid` | The payload is missing, too large or inconsistent |
| `ci_path_refused` | A path input is outside the workspace, a link or not a regular file |
| `ci_input_invalid` | An input has a value outside its allowed set |
| `ci_run_missing` | `gazua run` produced no `run.json` |
| `ci_projection_invalid` | The run cannot produce the CI summary |
| `ci_comment_permission` | The token cannot comment; the gate is kept |
| `ci_comment_failed` | The comment API refused or failed; the gate is kept |
| `ci_sarif_upload_failed` | The SARIF upload failed; the gate is kept |
| `ci_evidence_upload_failed` | Requested evidence was not uploaded; exit 2 |
| `sarif_profile_invalid` | The SARIF file could not be built; nothing was uploaded |

No message ever repeats an API response, a URL, a token or text from the event payload.
