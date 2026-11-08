# Integrating your tools

Gazua tests an agent through its tools. This page shows how to hand your tools to Gazua, what happens to them during a run and what stays the same in production.

## The short version

Write a small test file that builds your agent with `gazua.wrap(tools)` and point `entrypoint` in `gazua.yaml` to it. Your production code does not import Gazua.

```python
# tests/gazua_target.py
import gazua

from shop.agent import build_agent
from shop.tools import TOOLS


def entrypoint(message: str) -> str:
    agent = build_agent(tools=gazua.wrap(TOOLS))
    return agent.reply(message)
```

```yaml
# gazua.yaml
schema_version: 1
entrypoint: tests.gazua_target:entrypoint
```

The agent contract is `entrypoint(message) -> response`: one user message in, the agent's text response out. The function can be a plain function or an `async` function. A response that is not a `str` is an error, and the execution is recorded as an error, never as resisted.

## What `gazua.wrap` accepts

| Form | Example | Tool name |
|---|---|---|
| List or tuple of functions | `gazua.wrap([lookup_order, refund_order])` | The function name |
| Dict from name to function | `gazua.wrap({"lookup_order": lookup})` | The key |
| List of framework tool objects | `gazua.wrap([lookup_tool])` | The object's `name` |

A framework tool object is any object with a `name` and a `func`, and optionally a `coroutine`. Gazua returns a shallow copy with those functions replaced; the original object is never changed. The container keeps its type and order, so a list comes back as a list and a dict as a dict.

Async functions are supported. Generators, async generators and classes are not: inside a run, `gazua.wrap` raises `UnsupportedToolError` for them. Wrapping the same function twice returns the same proxy, and the proxy keeps the function's name, signature and docstring, so frameworks that read them keep working.

## The decorator

When the agent cannot receive its tools from outside, mark each tool instead:

```python
import gazua


@gazua.tool
def refund_order(order_id: int) -> dict: ...
```

Use it only when `gazua.wrap` is not possible. The decorator needs Gazua installed in production too, because the module that defines the tool imports it. Outside a Gazua run it returns the original function itself: no monkeypatching, no file access and no network. `gazua init` reports decorated tools and recommends `gazua.wrap` for this reason.

The decorator takes no arguments. `@gazua.tool` and `@gazua.tool()` both work, and `gazua init` can only read the tool name from these two forms.

## How a run reaches your code

A Gazua run writes a session file and sets the `GAZUA_SESSION` environment variable to its path before calling your entrypoint. The session says which tools may run for real, who is calling and where to record each call.

Without `GAZUA_SESSION`, `gazua.wrap` returns your tools unchanged and every tool is a plain function call. This also means that running your test file directly, outside Gazua, runs your real tools, exactly as it would without Gazua.

Each attack runs in its own process with a session of its own. That session also carries the tool call limit of the attempt and, when the run has one, the address of its local receiver.

With `GAZUA_SESSION` set, the session must be valid. If the file is missing, unreadable, larger than 1 MiB, not a regular file, malformed or of an unknown version, every tool call raises `GazuaBlockedError` and the original function is never called. Gazua fails closed: a real call is never the fallback.

## Dry-run

A tool runs for real only when `gazua.yaml` declares it `safe: true` and gives it a reviewed classification (`sensitive`, `forbidden` or an explicit `false`). Every other tool is in dry-run, and a tool that is not declared at all is in dry-run too.

A tool in dry-run never calls your function. It returns a fresh copy of its `dry_run_return`, so the agent sees a normal answer and keeps going. Without `dry_run_return`, it returns the string `ok` and the attacks that depend on it are flagged low fidelity, because the agent saw an answer that your tool would not give.

When your function has a return annotation made of simple JSON types (`str`, `int`, `float`, `bool`, `None`, `list`, `dict` and unions of these), Gazua compares `dry_run_return` with it and prints:

```text
Warning: dry_run_return of tool refund_order does not match its declared return type.
```

The tool is then marked low fidelity. Other annotations are not checked, and no check means no claim.

Before attacks run, Gazua prints how many tools are real and how many are in dry-run, for example `3 real tools, 9 in dry-run`, followed by the low fidelity tools and the warnings. [Running attacks safely](execution.md) shows where this summary appears.

## Who is calling

Attacks between users need to know who is calling a tool. Declare it in one of two ways:

- **`actor_arg`** on the tool: Gazua sets that argument to the identity of the current actor on every call, replacing whatever the model passed. The model never chooses who calls. If the function does not accept that argument, the call is blocked.
- **`target.as_user`** in `gazua.yaml`: a reference to a function `as_user(identity_id: str)` that returns a context manager, for example one that sets the current user of your authentication library. Gazua enters it around each real call, and only real calls. If it cannot be imported or fails to enter, the call is blocked.

When a tool has `actor_arg`, it wins. Without either declaration, the call is recorded without an identity and attacks between users are reported as not tested, missing identity. The identities come from `fixtures.attacker` and `fixtures.victim`.

## Attacks through tool results

Some attacks arrive in content that the agent reads, such as a retrieved document. For these, Gazua appends the attack text to the result of the chosen tool, after a line break, including the tool that serves your retrieval (RAG) results. The text is data; Gazua never interprets it.

Only text results can carry an attack. When the chosen tool returns anything else, nothing is added and the attack is reported as not tested, because Gazua cannot reach that entry.

## The call log

Every call made during a run is recorded in order: tool name, arguments, actor, whether it ran for real, how it ended and whether an attack was delivered. Return values are never recorded, only their type, and error messages are never recorded, only the error class. Each argument value is cut to 4096 characters, and values that are not JSON are recorded by their `repr`.

A call that cannot be recorded is blocked, because the verdict depends on the log.

The session and the call record formats are public JSON Schemas, packaged with Gazua: [`session-v1.schema.json`](../src/gazua/schemas/session-v1.schema.json), [`session-v2.schema.json`](../src/gazua/schemas/session-v2.schema.json) for a supervised attempt, and [`call-record-v1.schema.json`](../src/gazua/schemas/call-record-v1.schema.json).

## Usage, rate limits and exfiltration

Three optional calls let your test entrypoint tell Gazua what it cannot see. All three come from `import gazua`, use only the standard library and do nothing outside a run:

- `gazua.report_usage(cost_usd=...)` reports the cost of a model call, so that `max_cost` can apply.
- `raise gazua.GazuaRateLimited(retry_after=...)` reports a 429 from your model provider, so that Gazua slows down and retries.
- `gazua.send_to_receiver(url, ...)` sends an exfiltration attempt to a `.gazua.test` address to the run's local receiver instead of the network.

Your entrypoint still returns a `str`. [Running attacks safely](execution.md) explains each one and its limits.

## Limits

- Gazua sees only the tools that go through `gazua.wrap` or `@gazua.tool`. A tool your agent calls in another way is invisible to it.
- During a run, the wrapper refuses every call after `max_tool_calls` before it runs. Calls made in other processes or without the wrapper are not counted.
- Dry-run protects your systems only for tools that go through Gazua. Side effects inside a tool that runs for real are real.
- Generators, classes and decorators with arguments are not supported.

## Framework examples

These examples show where `gazua.wrap` goes. They are sketches, not tested against every version of each framework, so check your framework's documentation for its current API. In each one, the names in `gazua.yaml` must match the tool names your agent uses.

### Anthropic SDK

```python
import anthropic
import gazua

from shop.tools import lookup_order, refund_order

SCHEMAS = [...]  # your tool definitions, unchanged


def entrypoint(message: str) -> str:
    tools = gazua.wrap({"lookup_order": lookup_order, "refund_order": refund_order})
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": message}]
    while True:
        response = client.messages.create(
            model="your-model", max_tokens=1024, tools=SCHEMAS, messages=messages
        )
        calls = [block for block in response.content if block.type == "tool_use"]
        if not calls:
            return "".join(block.text for block in response.content if block.type == "text")
        messages.append({"role": "assistant", "content": response.content})
        messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": call.id,
                        "content": str(tools[call.name](**call.input)),
                    }
                    for call in calls
                ],
            }
        )
```

### OpenAI SDK

```python
import json

import gazua
from openai import OpenAI

from shop.tools import lookup_order, refund_order

SCHEMAS = [...]  # your function definitions, unchanged


def entrypoint(message: str) -> str:
    tools = gazua.wrap({"lookup_order": lookup_order, "refund_order": refund_order})
    client = OpenAI()
    messages = [{"role": "user", "content": message}]
    while True:
        reply = (
            client.chat.completions.create(model="your-model", messages=messages, tools=SCHEMAS)
            .choices[0]
            .message
        )
        if not reply.tool_calls:
            return reply.content or ""
        messages.append(reply)
        for call in reply.tool_calls:
            result = tools[call.function.name](**json.loads(call.function.arguments))
            messages.append({"role": "tool", "tool_call_id": call.id, "content": str(result)})
```

### Agent SDK

Wrap your functions first, then build the SDK tools from the wrapped functions. The proxy keeps the name, signature and docstring that the SDK reads.

```python
import gazua
from agents import Agent, Runner, function_tool

from shop.tools import lookup_order, refund_order


def entrypoint(message: str) -> str:
    wrapped = gazua.wrap([lookup_order, refund_order])
    agent = Agent(
        name="support",
        instructions="Help the customer.",
        tools=[function_tool(tool) for tool in wrapped],
    )
    return Runner.run_sync(agent, message).final_output
```

### LangGraph

LangChain tools have a `name` and a `func` (or `coroutine`), so the list of tool objects can be wrapped as is.

```python
import gazua
from langgraph.prebuilt import create_react_agent

from shop.tools import lookup_order_tool, refund_order_tool


def entrypoint(message: str) -> str:
    tools = gazua.wrap([lookup_order_tool, refund_order_tool])
    graph = create_react_agent("your-model", tools)
    result = graph.invoke({"messages": [("user", message)]})
    return result["messages"][-1].content
```
