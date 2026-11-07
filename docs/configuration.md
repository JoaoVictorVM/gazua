# Configuration

A project tested by Gazua is described by one file, `gazua.yaml`, at the project root. This page covers how to create it, what to review and what each field means.

## Treat `gazua.yaml` as code

`entrypoint`, `target.reset`, `target.as_user` and `output_sink` point to Python functions. A future execution of Gazua can import and call them, so a change to this file can run code on your machine or in your CI. Review it the way you review code, including changes that arrive from other people.

Reading the file does not run anything. `gazua init` and the configuration loader treat references as text and never import your project.

## Create the file

```console
gazua init
gazua init path/to/project --entrypoint tests.gazua_target:entrypoint
```

`gazua init` does the following:

1. Stops with exit code 2 if `gazua.yaml` already exists. The existing file is kept. There is no option to overwrite it.
2. Reads the `.py` files under the project, without following symlinks. It skips version control, virtual environment, dependency, build, cache and local agent directories. It does not read `.env` or key files.
3. Lists the tools it found and the class suggested for each one.
4. Writes `gazua.yaml`, with a `REVIEW REQUIRED` comment on each suggestion and `safe: false` on every tool.
5. Adds `.gazua/` to `.gitignore`, creating the file when needed and keeping what is already there. If a rule re-includes the directory, a new rule is added at the end and a warning is printed.

If `.gitignore` cannot be updated after the configuration was created, the command exits with code 2, says what was created and what is left for you to do. It does not remove any file.

### What discovery can see

Discovery reads the syntax of your files. It does not import them. It recognizes:

```python
import gazua
import gazua as g
from gazua import tool, wrap
from gazua import wrap as w

tools = gazua.wrap([get_order, send_email])
tools = g.wrap((get_order, send_email))

declared = [get_order, send_email]  # assigned once in the same module
tools = w(declared)


@gazua.tool
def get_order(order_id): ...


@tool()
async def send_email(to): ...
```

Names can come from functions defined at the top level of the module or from explicit imports such as `from shop.tools import get_order`.

These forms produce a warning and need a manual declaration: computed lists, lists that are reassigned or changed, star imports, attribute references such as `shop.get_order`, factories, closures, methods, decorators with arguments and files that do not parse. Two distinct functions with the same name also produce a warning. A warning means discovery is incomplete. It does not mean that a tool does not exist.

`entrypoint` is filled in only when the project has a single top-level function named `entrypoint` and its module path is clear. Otherwise it stays `null` for you to fill in.

### What a suggestion means

Tools whose names start with `delete_`, `refund_`, `send_`, `update_`, `write_` or `execute_` are suggested as `sensitive: true`, ignoring case. All the others stay unclassified.

A suggestion comes from the name only. It proves nothing about what the tool does or about who may call it. Gazua never suggests `forbidden: true` or `safe: true`. Those decisions are yours.

## Fields

Only `schema_version` is required. A file without `entrypoint` or without tools is valid and can be edited, but it is not ready to test anything yet.

| Field | Type | Without it | Notes |
|---|---|---|---|
| `schema_version` | the integer `1` | Error | Other versions need an explicit migration |
| `entrypoint` | reference or `null` | `null` | `module:attribute` |
| `target.reset` | reference or `null` | `null` | Hook without arguments |
| `target.as_user` | reference or `null` | `null` | Context manager factory that receives an identity |
| `tools` | map of name to tool | Empty | One declaration per name |
| `limits` | object | Defaults below | |
| `fixtures` | object | Empty | Synthetic `attacker` and `victim` identities |
| `canaries` | list of unique strings | Empty | Test values only |
| `output_sink` | reference or `null` | `null` | |
| `gate.fail_on` | unique list of `low`, `medium`, `high`, `critical` | `[high, critical]` | An empty list turns the severity gate off |
| `legit_tasks` | list of `request` and `expected_tool` | Empty | |
| `allowed_targets` | list of exact hosts | `localhost`, `127.0.0.1`, `::1` | No scheme, path, port or wildcard. An empty list authorizes no host |

### Tools

| Field | Type | Without it | Notes |
|---|---|---|---|
| `safe` | boolean | `false` | Declares that the tool is safe to run on test data |
| `sensitive` | boolean or `null` | Not declared | `false` counts as a reviewed classification |
| `forbidden` | boolean or `null` | Not declared | `true` takes priority over `sensitive` |
| `owner_arg` | Python argument name or `null` | Not declared | |
| `actor_arg` | Python argument name or `null` | Not declared | |
| `dry_run_return` | any JSON value | Not declared | `null` is a deliberate return value, different from leaving it out |

The class of a tool comes from these flags: `forbidden: true` makes it forbidden, otherwise `sensitive: true` makes it sensitive, otherwise an explicit `false` makes it regular. With neither flag it is unclassified.

To run for real, a tool needs both `safe: true` and a reviewed classification. An unclassified tool stays in dry-run even with `safe: true`.

### Limits

| Field | Type | Default |
|---|---|---|
| `max_runs` | positive integer | `300` |
| `timeout` | positive number of seconds | `120` |
| `max_tool_calls` | positive integer | `50` |
| `concurrency` | positive integer | `2` |
| `max_cost` | positive number in USD or `null` | `null` |
| `cost_per_run` | non-negative number in USD or `null` | `null` |

### Fixtures

```yaml
fixtures:
  attacker:
    id: GAZUA-attacker
  victim:
    id: GAZUA-victim
    records:
      - tool: get_order
        id_arg: order_id
        id: GAZUA-order-1
canaries:
  - GAZUA-CANARY-ONLY-TEST
```

The two identities must have different ids, and every `tool` must be declared under `tools`. Each side is optional.

## What happens when a declaration is missing

A missing declaration does not make the file invalid. The features that use it apply these results:

| Missing | Result |
|---|---|
| `sensitive`, `forbidden` | Warning; the tool stays in dry-run |
| `owner_arg` | Dependent attacks are not tested, missing owner_arg |
| `actor_arg` and `target.as_user` | IDOR attacks are not tested, missing identity |
| `fixtures`, canary | Dependent attacks are not tested |
| `safe: true` | Not tested in tools mode; dry-run in agent mode |
| `dry_run_return` | Generic `ok` return; attacks flagged low fidelity |
| `legit_tasks` | Legitimate use: not tested |
| `output_sink` | Conditional risk, not verified |
| `target.reset` | Memory attacks are not tested |
| `allowed_targets` | Localhost only |

Attack execution has not shipped yet. Today the loader reports these absences, and the commands that use them will apply the results when they ship.

## YAML rules

The file is one UTF-8 document with a mapping at the top, up to 1 MiB and 64 levels deep. Values are limited to what JSON can represent. These are rejected:

- All explicit tags, such as `!!python/object/apply`, `!custom` and `!!binary`
- Aliases, anchors and merge keys
- Repeated keys and keys that are not strings
- Unquoted dates, `.nan` and `.inf`
- More than one document

Only `true` and `false` are booleans, so names like `on`, `off`, `yes` and `no` stay text. Numbers must be written in plain decimal notation: `010`, `0x10` and `1_000` stay text. Types are strict, so `"3"` is not a number and `"false"` is not a boolean.

Environment variables are not expanded. `${OPENAI_API_KEY}` is only that text.

## Errors

A problem in the file exits with code 2 and names the file, line, column and field:

```text
gazua.yaml:12:5: limits.max_runs: Expected an integer greater than zero.
```

Messages do not repeat the values from your file.

## Test values and secrets

Canaries and fixtures must be fake. If a string in the file has the format of a known key, loading stops with this message, without showing the value:

```text
gazua.yaml:8:5: canaries[0]: Canaries and fixtures must be test values; this looks like a real key.
```

The check looks for known key formats and private key headers. It works offline and does not find every possible secret. A `GAZUA-` prefix is recommended for fake values, but it does not exempt a value that has the format of a key.

## JSON Schema

The schema is at [`src/gazua/schemas/config-v1.schema.json`](../src/gazua/schemas/config-v1.schema.json) and ships inside the package. Generated files include a comment that points editors using `yaml-language-server` to it. `gazua init` does not access the network.

The schema covers structure and types. The loader also checks what a schema cannot express:

- Tool references in `fixtures` and `legit_tasks`
- Different attacker and victim ids
- Python keywords in references and argument names
- Valid IPv6 addresses in `allowed_targets`
- The strict YAML rules above
- Key formats in test values
