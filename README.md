# Gazua

Gazua is an open source security test suite for AI agents. It attacks an agent the way an attacker would, then verifies in code whether the attack had a real effect, using a fixed catalog of attacks.

Other tools ask whether the model refused; Gazua proves whether the code stops the attack.

## Try it in two commands

```console
uv tool install gazua
gazua demo
```

`gazua demo` attacks a fictional store support assistant, first by calling its tools directly and then through a scripted model, and opens a page with both reports. It needs no API key, no configuration and no network connection. **The scripted model shows that Gazua and the controls it exercises work; it does not measure how a real model resists attacks.** Until the first stable release, add the version to the install command, as shown under [Installation](#installation). See [the demo guide](docs/demo.md), which also covers the Docker image.

> **Status: early pre-release.** This package contains the project foundation, project configuration, the attack catalog, the tool integration API tools mode, agent mode, their reports and the demo: `gazua --help`, `gazua --version`, `gazua init`, `gazua run --list`, `gazua run --tools`, `gazua run --agent`, `gazua report`, `gazua clean`, `gazua demo`, `gazua.wrap` and `@gazua.tool`. Gazua makes no claim about the resistance of any agent.

## Installation

The first build is the development version `0.1.0.dev0`. Pre-releases have to be selected explicitly, so include the version once it is available on PyPI:

```console
uv tool install gazua==0.1.0.dev0
pip install gazua==0.1.0.dev0
```

A plain `uv tool install gazua` or `pip install gazua` applies from the first stable release onward.

### Supported platforms

Every change is verified on Windows and Ubuntu with Python 3.11 and Python 3.14. Gazua requires Python 3.11 or newer, but only the versions listed here have been verified. A new Python version is added to this list after the test suite passes on it.

## What is available today

| Command | What it does |
|---|---|
| `gazua` or `gazua --help` | Shows the help |
| `gazua --version` | Shows the installed version |
| `gazua init` | Finds the tools in a project by reading its source code and writes `gazua.yaml` for your review |
| `gazua run --list` | Lists the attack catalog by damage and mode, with what each attack needs from `gazua.yaml`. Nothing is executed |
| `gazua run --tools` | Calls your `safe: true` tools directly as the attacker, with no model and no key, and writes `.gazua/report.html`, `report.md` and `run.json`. Exit code 0, 1 on a gated finding, 2 on an error |
| `gazua baseline` | Accepts the findings of the last saved run as known, in a versionable `gazua-baseline.json`. Later runs fail only on new gated findings, and say how many were known. Nothing is executed |
| `gazua verify <finding>` | Repeats an accepted finding's attack 20 times per scenario. Only 0 in 20 (up to ~14%) closes it; any success keeps it open. Exit code 0 closed, 1 still open, 2 interrupted or incomplete |
| `gazua report --from .gazua/run.json` | Rebuilds `report.html` and `report.md` from a run document, offline. Nothing is executed |
| `gazua issues` | Writes one Markdown issue per finding of the last saved run to `.gazua/issues/<run-id>/`, with the fix guide, the confirmation command and acceptance criteria, ready to copy into a backlog. Offline; it never opens issues on any service |
| `gazua clean` | Removes Gazua's runs, reports, evidence and issue exports from `.gazua/`. The last 20 runs are kept automatically |
| `gazua demo` | Runs tools mode and agent mode against a fictional, deliberately vulnerable store with a scripted model, in `./gazua-demo`, and opens a page with both reports. No key, configuration or network. Exit code 1 is the expected result |
| `python -m gazua` | Same behavior as `gazua` |

Tools mode is described in [the tools mode guide](docs/tools-mode.md), and its reports, masking, regeneration and retention in [the reports guide](docs/reports.md). `gazua run --agent` sends the attacks to your real agent, which uses its own model and key, repeats each one 5 times and measures legitimate tasks too; `--quick` runs about 15 molds once. It is meant for nightly and pre-release runs and is described in [the agent mode guide](docs/agent-mode.md). Other commands will appear in the help only when they ship. The engine that runs each attack in its own process, with a timeout, a tool call limit, a run limit and a local receiver for exfiltration attempts, is described in [the execution guide](docs/execution.md). How recorded effects become one state per attack, with its rate, upper bound and proof, is described in [the verdict guide](docs/verdicts.md). Accepting known findings, comparing runs with them and verifying fixes are described in [the baseline guide](docs/baseline.md). What fixes each damage, and how to confirm a fix, is in [the fix guide](docs/fix-guide.md); exporting findings as issues is described in [the issue export guide](docs/issues.md). MCP servers in any language are tested over stdio with the `gazua[mcp]` extra, `gazua init --mcp` and `gazua mcp-proxy`, described in [the MCP guide](docs/mcp.md).

## Integrating your tools

Build your agent in a small test file with `gazua.wrap(tools)` and point `entrypoint` in `gazua.yaml` to it, so production code imports nothing from Gazua. During a run, every tool that `gazua.yaml` does not declare `safe: true` returns its declared `dry_run_return` instead of running, and every call is recorded. Outside a run, your tools are plain function calls. The `@gazua.tool` decorator is the alternative when tools cannot be passed in, and it needs Gazua installed in production. See [the integration guide](docs/integration.md).

## Configuration

`gazua init` writes a `gazua.yaml` with suggestions marked `REVIEW REQUIRED` and adds `.gazua/` to `.gitignore`. It never imports your project, and it never marks a tool as safe.

`gazua.yaml` can execute code, because `entrypoint` and the target hooks point to Python functions that a future execution can call. Review it the way you review code.

See [the configuration guide](docs/configuration.md) for the fields, the limits of tool discovery and what happens when a declaration is missing. The JSON Schema is at [`src/gazua/schemas/config-v1.schema.json`](src/gazua/schemas/config-v1.schema.json).

## Attack catalog

Each attack is a mold: damage + entry + technique, with English and Portuguese text, the modes that can use it and the effect that proves it worked. Molds are data, and you can add your own in YAML so that a past incident becomes a permanent test. Third-party catalogs are local folders that you review; they cannot change your target, tools or dry-run settings, and Gazua prints a warning before reading them. See [the mold guide](docs/molds.md).

## Self-test benchmark

Gazua is tested against itself: every mold must fire on a deliberately vulnerable synthetic target and stay quiet on a hardened one, turning off one control at a time must show exactly that control's finding, and no tool that is not `safe: true` may really run. Contributors run it with no key, and CI blocks a mold that does not pass both checks. See [the benchmark guide](docs/benchmark.md).

The table below is generated from an observed run of the release profile, never edited by hand; rates keep their denominators and a missing implementation shows as pending, not as parity.

<!-- benchmark:start -->
Profile `release`, catalog `v0.1`, status `passed`, commit `a6bc093b634d`, matrix revision `2026-11-17.1`.

- Molds fired where expected: 100.0% (30/30)
- False alarms on targets that must stay quiet: 0.0% (0/18)
- Controls detected by one-at-a-time mutation: 100.0% (7/7)
- Auxiliary checks passed: 100.0% (7/7)

| Implementation | Mode | Language | Detection | False alarms | Unexpected findings | Coverage | Pending | Errors |
|---|---|---|---|---|---|---|---|---|
| python | tools | en | 100.0% (15/15) | 0.0% (0/9) | 0 | 100.0% (45/45) | 0 | 0 |
| python | tools | pt | 100.0% (15/15) | 0.0% (0/9) | 0 | 100.0% (45/45) | 0 | 0 |

Simulated runs measure Gazua's own chain against synthetic targets with a scripted model. They are not a resistance rate of any commercial model.
<!-- benchmark:end -->

## Threat model

Gazua is designed around three actors:

1. **A user abusing the company:** someone with legitimate access uses the agent to reach what they should not, such as another customer's records.
2. **A third party abusing the user through the agent:** text planted in content the agent reads steers it against the person it is working for.
3. **The agent erring alone:** with no attacker involved, the agent takes a harmful or out-of-scope action on its own.

## Authorized use only

Use Gazua only on systems you own or have written authorization to test.

When a test involves a real model, attack text reaches the model provider and may trigger its abuse filters. Check the provider's terms before testing, and expect possible consequences for the account in use.

## What a passing result means

Passing is a floor, not a ceiling. The catalog is fixed and attacks are not adaptive, so a clean result shows that the agent resists these attacks. It does not show that the agent is secure, and Gazua publishes no badge or seal of approval.

## Privacy

Gazua collects no telemetry. There is no telemetry of any kind, and no account or hosted service is required. Gazua never asks for, reads or stores model provider keys.

## Security

To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
