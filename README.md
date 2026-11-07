# Gazua

Gazua is an open source security test suite for AI agents. It attacks an agent the way an attacker would, then verifies in code whether the attack had a real effect, using a fixed catalog of attacks.

Other tools ask whether the model refused; Gazua proves whether the code stops the attack.

> **Status: early pre-release.** This package contains the project foundation only: `gazua --help` and `gazua --version`. It cannot run attacks yet, and it makes no claim about the resistance of any agent.

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
| `python -m gazua` | Same behavior as `gazua` |

Attack execution, reports and project configuration are planned, and their commands will appear in the help only when they ship.

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
