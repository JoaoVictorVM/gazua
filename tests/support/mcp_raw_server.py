"""Synthetic MCP server over stdio, standard library only, driven by a JSON scenario file.

It answers ``initialize``, ``tools/list`` (with the pages the scenario declares, read again on
every listing so a test can change them mid-run) and ``tools/call``. Every call that reaches it
is appended to the scenario's ``calls_file``, which is how tests prove what was forwarded. The
records and identities are synthetic test data.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any


def _send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def _pages(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    source = scenario.get("tools_file")
    data = json.loads(Path(source).read_text(encoding="utf-8")) if source else scenario
    return list(data["pages"])


def _record(scenario: dict[str, Any], name: str, arguments: dict[str, Any]) -> None:
    path = scenario.get("calls_file")
    if path:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"tool": name, "arguments": arguments}) + "\n")


def _call(scenario: dict[str, Any], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "get_order":
        order = str(arguments.get("order_id"))
        owner = scenario.get("orders", {}).get(order)
        actor = arguments.get("actor_id")
        if owner is None or (scenario.get("mode") == "hardened" and owner != actor):
            return {"content": [{"type": "text", "text": "{}"}], "structuredContent": {}}
        record = {"order_id": order, "owner_id": owner, "status": "shipped"}
        return {
            "content": [{"type": "text", "text": json.dumps(record)}],
            "structuredContent": record,
            "isError": False,
        }
    if name == "fail":
        return {"content": [{"type": "text", "text": "Application error."}], "isError": True}
    if name == "mixed":
        return {
            "content": [
                {"type": "text", "text": "first"},
                {"type": "image", "data": "AAAA", "mimeType": "image/png"},
            ]
        }
    return {"content": [{"type": "text", "text": f"{name} done"}], "isError": False}


def main() -> int:
    scenario = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if scenario.get("pid_file"):
        with Path(scenario["pid_file"]).open("a", encoding="utf-8") as handle:
            handle.write(f"{os.getpid()}\n")
    if scenario.get("environment_file"):
        Path(scenario["environment_file"]).write_text(
            json.dumps(sorted(os.environ)), encoding="utf-8"
        )
    if scenario.get("exit_on_start"):
        return 3
    if scenario.get("sleep_on_start"):
        time.sleep(float(scenario["sleep_on_start"]))
    for raw in sys.stdin:
        if not raw.strip():
            continue
        message = json.loads(raw)
        method, ident = message.get("method"), message.get("id")
        if ident is None:
            continue
        if method == "initialize":
            requested = message["params"]["protocolVersion"]
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": ident,
                    "result": {
                        "protocolVersion": scenario.get("protocol_version") or requested,
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {"name": "synthetic", "version": "1.0.0"},
                    },
                }
            )
        elif method == "tools/list":
            if scenario.get("oversized_listing"):
                sys.stdout.write("{" + " " * (1024 * 1024 + 10) + "}\n")
                sys.stdout.flush()
                continue
            pages = _pages(scenario)
            cursor = (message.get("params") or {}).get("cursor")
            index = 0 if cursor is None else int(cursor.split("-")[1])
            page = pages[index]
            result: dict[str, Any] = {"tools": page["tools"]}
            if page.get("next") is not None:
                result["nextCursor"] = page["next"]
            _send({"jsonrpc": "2.0", "id": ident, "result": result})
        elif method == "tools/call":
            params = message["params"]
            name, arguments = params["name"], params.get("arguments") or {}
            _record(scenario, name, arguments)
            if scenario.get("hang_on_call"):
                time.sleep(3600)
            _send({"jsonrpc": "2.0", "id": ident, "result": _call(scenario, name, arguments)})
        elif method == "ping":
            _send({"jsonrpc": "2.0", "id": ident, "result": {}})
        else:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": ident,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
