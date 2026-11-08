# Gazua

Gazua is an open source security test suite for AI agents. It attacks an agent the way an attacker would, then verifies in code whether the attack had a real effect, using a fixed catalog of attacks.

Other tools ask whether the model refused; Gazua proves whether the code stops the attack.

> **Status: early pre-release.** This package contains the project foundation, project configuration, the attack catalog and the tool integration API: `gazua --help`, `gazua --version`, `gazua init`, `gazua run --list`, `gazua.wrap` and `@gazua.tool`. It cannot run attacks yet, and it makes no claim about the resistance of any agent.

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
| `python -m gazua` | Same behavior as `gazua` |

Attack execution and reports are planned. `gazua run` only lists the catalog for now, and other commands will appear in the help only when they ship. The engine that runs each attack in its own process, with a timeout, a tool call limit, a run limit and a local receiver for exfiltration attempts, is described in [the execution guide](docs/execution.md).

## Integrating your tools

Build your agent in a small test file with `gazua.wrap(tools)` and point `entrypoint` in `gazua.yaml` to it, so production code imports nothing from Gazua. During a run, every tool that `gazua.yaml` does not declare `safe: true` returns its declared `dry_run_return` instead of running, and every call is recorded. Outside a run, your tools are plain function calls. The `@gazua.tool` decorator is the alternative when tools cannot be passed in, and it needs Gazua installed in production. See [the integration guide](docs/integration.md).

## Configuration

`gazua init` writes a `gazua.yaml` with suggestions marked `REVIEW REQUIRED` and adds `.gazua/` to `.gitignore`. It never imports your project, and it never marks a tool as safe.

`gazua.yaml` can execute code, because `entrypoint` and the target hooks point to Python functions that a future execution can call. Review it the way you review code.

See [the configuration guide](docs/configuration.md) for the fields, the limits of tool discovery and what happens when a declaration is missing. The JSON Schema is at [`src/gazua/schemas/config-v1.schema.json`](src/gazua/schemas/config-v1.schema.json).

## Attack catalog

Each attack is a mold: damage + entry + technique, with English and Portuguese text, the modes that can use it and the effect that proves it worked. Molds are data, and you can add your own in YAML so that a past incident becomes a permanent test. Third-party catalogs are local folders that you review; they cannot change your target, tools or dry-run settings, and Gazua prints a warning before reading them. See [the mold guide](docs/molds.md).

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
