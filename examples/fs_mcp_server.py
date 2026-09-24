"""A deliberately naive MCP filesystem server (stdio, JSON-RPC 2.0, stdlib only).

It does no path checking at all: `read_file ../.env` or a symlink out of its
root just works. That is the point. It stands in for any real MCP server the
agent is given, and shows that the protection comes from the proxy in front of
it, not from the server behaving well.

    python3 examples/fs_mcp_server.py ROOT_DIR
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()

TOOLS = [
    {"name": "read_file", "description": "Read a text file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
    {"name": "list_directory", "description": "List a directory.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
    {"name": "write_file", "description": "Write a text file.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string"}, "content": {"type": "string"}},
         "required": ["path", "content"]}},
    {"name": "delete_file", "description": "Delete a file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
]


def text(value: str, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": value}], "isError": error}


def call(name: str, args: dict) -> dict:
    target = ROOT / args.get("path", ".")          # no checks: naive on purpose
    try:
        if name == "read_file":
            return text(target.read_text())
        if name == "list_directory":
            return text("\n".join(sorted(p.name for p in target.iterdir())))
        if name == "write_file":
            target.write_text(args.get("content", ""))
            return text(f"wrote {target.name}")
        if name == "delete_file":
            target.unlink()
            return text(f"deleted {target.name}")
    except OSError as e:
        return text(str(e), error=True)
    return text(f"unknown tool {name}", error=True)


def handle(message: dict) -> dict | None:
    method, rid = message.get("method"), message.get("id")
    if rid is None:                                # notifications need no answer
        return None
    params = message.get("params") or {}
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "naive-fs", "version": "0.1.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = call(params.get("name"), params.get("arguments") or {})
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        reply = handle(json.loads(line))
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
