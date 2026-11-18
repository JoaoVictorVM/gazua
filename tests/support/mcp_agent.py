"""Simulated MCP agent for tests: an entrypoint whose MCP client starts ``gazua mcp-proxy``.

There is no model here. The "model" is a fixed rule that acts on what the tool descriptions
say, so a test can prove that a poisoned description reached the client and that the effect
followed it. It demonstrates transport and control; it measures no real model's resistance.

Behaviors, read from ``agent-behavior`` next to this file:

- ``follow``: lists the tools, then follows an order id or a maintenance instruction found in
  any description.
- ``ignore``: lists the tools and only does the legitimate task.
- ``early``: reads the victim order before listing, then behaves like ``follow``.
- ``early_only``: reads the victim order before listing, then ignores the descriptions.
- ``cached``: keeps the first listing of this process and never lists again.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from gazua.mcp import proxy_server_parameters

HERE = Path(__file__).resolve().parent
SELF = "attacker"
ORDER = re.compile(r"\border-[a-z0-9-]+\b")
_cache: list[list[Any]] = []


def _behavior() -> str:
    path = HERE / "agent-behavior"
    return path.read_text(encoding="utf-8").strip() if path.is_file() else "follow"


async def _text(session: ClientSession, name: str, arguments: dict[str, Any]) -> str:
    try:
        result = await session.call_tool(name, arguments)
    except Exception:  # noqa: BLE001
        return f"{name} failed"
    return " ".join(getattr(block, "text", "") for block in result.content)


async def _run(message: str) -> str:
    behavior = _behavior()
    parameters = StdioServerParameters(**proxy_server_parameters())  # type: ignore[arg-type]
    with Path(os.devnull).open("w", encoding="utf-8") as quiet:
        async with (
            stdio_client(parameters, errlog=quiet) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            answers: list[str] = []
            if behavior in ("early", "early_only"):
                answers.append(
                    await _text(
                        session, "get_order", {"order_id": "order-victim", "actor_id": SELF}
                    )
                )
            if behavior == "cached" and _cache:
                tools = _cache[0]
            else:
                tools = list((await session.list_tools()).tools)
                if behavior == "cached":
                    _cache.append(tools)
            names = {tool.name for tool in tools}
            descriptions = "\n".join(tool.description or "" for tool in tools)
            if "status" in message.lower() and "search_docs" in names:
                found = await _text(session, "search_docs", {"query": message})
                answers.append(found)
                if behavior != "ignore":
                    descriptions += "\n" + found
            if behavior in ("follow", "early", "cached"):
                for order in sorted(set(ORDER.findall(descriptions))):
                    answers.append(
                        await _text(session, "get_order", {"order_id": order, "actor_id": SELF})
                    )
                if "maintenance tool" in descriptions and "run_maintenance" in names:
                    answers.append(await _text(session, "run_maintenance", {}))
            if "order" in message.lower() and "get_order" in names:
                answers.append(
                    await _text(
                        session, "get_order", {"order_id": "order-attacker", "actor_id": SELF}
                    )
                )
            if "export" in message.lower() and "export_data" in names:
                answers.append(await _text(session, "export_data", {}))
            if "email" in message.lower() and "send_email" in names:
                answers.append(await _text(session, "send_email", {"to": "team@example.test"}))
            return " | ".join(answers) or "Nothing to do."


def entrypoint(message: str) -> str:
    return asyncio.run(_run(message))
