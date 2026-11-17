# Self-test benchmark

The self-test benchmark checks Gazua against itself. It runs the real tools mode and agent mode, with their engine, verdicts and reports, against synthetic targets whose controls are known, and compares what Gazua persisted with a reviewed matrix of expectations. It is development infrastructure in `benchmarks/`; it is not part of the installed package and adds no `gazua` command.

```console
uv sync --frozen
uv run --frozen python -m benchmarks.selftest --profile release
```

It needs no API key, no model and no network connection after the dependencies are installed. Every run writes a new folder under `.gazua/benchmarks/` with `benchmark.json`, `summary.md` and the native reports of each run; earlier folders are never reused or deleted.

## What it checks

| Check | How |
|---|---|
| Every mold fires on the vulnerable target | The exact set of findings by mold, tool and signal, each with a proof in the reopened `run.json` |
| Hardened target stays quiet | No finding, with every scenario in the state the matrix declares |
| Target without tools | Tools mode proves every mold not applicable, with no call and exit code 0 |
| One control at a time | The hardened target with exactly one control off shows exactly that control's finding; the whole catalog shows the exact mapped set |
| Dry-run spy | Zero real calls of tools that are not `safe: true`, nested and async calls included, and no network or credential read in any process |
| Canary | Detected by its native signal; reports keep it only as a whole value; the aggregated result never carries it |
| Report HTML | Payloads stay inert under the report's content security policy |
| Legitimate tasks | The hardened target still serves its own users, so a target that refuses everything fails |
| Command line | `gazua run --tools` agrees with the programmatic run on exit code, states and findings |
| Properties and YAML | Hypothesis properties of verdicts and bounded fuzzing of the YAML data profile |

A finding the vulnerable target is expected to have is part of a passing result: the benchmark measures whether Gazua's chain conforms, not whether findings are absent. Exit code 0 means every selected cell conforms, 1 means a mismatch, an unexpected finding, a leak or a broken control, and 2 means an invalid matrix or option, a pending dependency, an interruption or a result that could not be saved.

## Profiles

| Profile | What it runs |
|---|---|
| `release` (default) | Every mold of the catalog release in the packaged manifest, both languages, every control mutation and every auxiliary check. This is the CI gate |
| `full` | Every mold of every release and every implementation in the support inventory. Cells whose dependency does not exist yet are reported as pending, and the result is incomplete |
| `real` | Manual and opt-in. It requires `--real-config`, a positive `--max-cost` and a positive `limits.cost_per_run` estimate in that configuration, and it never runs in CI. This version checks those conditions and starts nothing |

`--mold ID` and `--framework ID` narrow a run for diagnosis. A narrowed result says `scope: selection` and never proves a release or the full benchmark. `--max-runs` caps the engine; a cap that cuts the plan leaves scenarios not tested and fails the affected cells instead of shrinking the denominator.

## Targets and controls

All targets share one synthetic store: an attacker and a victim, orders, invoices and notes, one canary inside a victim's internal note, a refund, an account deletion, a partner notification that is never marked safe, and an output sink. A profile, fixed before any tool is registered, says which controls are on:

| Control | Hardened behavior |
|---|---|
| `order-ownership`, `invoice-ownership`, `note-ownership` | A user-scoped read returns only the actor's own records |
| `note-minimization` | Internal note fields never leave the store, even on a trusted service read |
| `forbidden-tool-exposure` | Tools mode: the deletion tool is neither registered nor declared. Agent mode: the target's dispatcher refuses it |
| `sensitive-operation` | Tools mode: refunds, partner notifications and paid reports are neither registered nor declared. Agent mode: the dispatcher refuses them |
| `output-escaping` | The sink escapes markup and removes control characters |

A refusal returned by a tool that is still exposed would still be a call, and dry-run is Gazua's protection, not a control of the target, so neither counts as hardening.

The target without tools proves inapplicability only where a tool is a prerequisite. Having no tools does not make an agent immune to leaking text or to unsafe output: in agent mode, molds that need no tool still run against it and are expected to resist. Agent mode does not yet prove that a target has no tools, so its tool-dependent molds stay not tested there instead of not applicable.

Agent mode uses a scripted model that reads only the user's message, the text results of the tools it calls and its short history. It never sees a mold id, the catalog, the matrix or an expected result. It stands in for a model so the chain can be checked without a key; it does not measure how any real model resists attacks.

## Support inventory

| Implementation | Status |
|---|---|
| Python, direct | Runs in every profile |
| Anthropic SDK | Pending: adapter over the SDK with an in-memory test transport |
| OpenAI Agents SDK | Pending: adapter over the runner with a scripted custom model and tracing disabled |
| LangGraph | Pending: adapter over a compiled graph with a scripted model node |
| MCP server in TypeScript | Pending: needs Gazua's MCP transport and proxy |
| Native TypeScript instrumentation | Pending: needs the TypeScript package |

Agent molds whose entry is a web page, an attachment or an MCP tool description, memory attacks and receiver attacks are pending until agent mode can deliver and observe them through a trusted adapter. Pending cells are never counted as detected, resisted or passed.

## The matrix

`benchmarks/selftest/matrix.json` is reviewed by hand. For each mold and implementation it declares the vulnerable, hardened and no-tool cases with the exact state of every scenario; for each control, the single finding of the isolated mutation and the exact set of the whole catalog. It is never generated from an observed result. A change to the catalog that is not reflected in the matrix fails before anything runs.

In CI, the release profile must pass. With a reliable Git base, every changed or new mold, of any release, must also have its executable target pair and pass it, so a mold whose cells are pending cannot be merged. Without a reliable base, such as a new tag, the release profile is the gate.

## Published numbers

The README table is generated from an observed run, never written by hand:

```console
uv run --frozen python -m benchmarks.selftest.publishing --from .gazua/benchmarks/<id>/benchmark.json
uv run --frozen python -m benchmarks.selftest.publishing --from .gazua/benchmarks/<id>/benchmark.json --check
```

The CI gate runs the check, so a hand edit or numbers made stale by a catalog change fail the build. Each rate keeps its denominator; a rate whose denominator is zero is shown as "not applicable". Detection counts a positive cell only when its whole expected set of findings appears with valid proofs and nothing else. False alarms count cells that must stay quiet and did not. The table and `benchmark.json` contain no payload, conversation, canary value, finding id or proof reference.

The result schema is `benchmarks/selftest/schemas/benchmark-v1.schema.json`. A consumer must check the schema version, the profile, the scope and the provenance: a passed selection, or a result without a commit, is not evidence of a release or of the full benchmark.
