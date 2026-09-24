"""MCP proxy: put the gateway between an MCP client and a real MCP server.

The client (Claude Code, an IDE, any MCP host) launches this proxy as if it were
the server; the proxy launches the real server and relays JSON-RPC over stdio.

- `tools/call` goes through the gateway: policy (registry + path arguments),
  audit, fail-closed. A blocked call never reaches the server; the client gets a
  tool result with `isError: true` that says which rule stopped it.
- `tools/list` is filtered: tools that are not in the registry are not even
  shown to the model.
- Everything else (initialize, notifications, pings, server-to-client requests)
  is relayed untouched.

Approval never reads stdin, because stdin is the MCP channel: an action that
requires approval is denied unless `--tty-approval` is given and a terminal is
available at /dev/tty.

    python -m agent_firewall.mcp_proxy --policy policies/default.json \\
        --audit logs/mcp-audit.jsonl --server-name filesystem \\
        -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir

Limitation: calls are handled one at a time; while a tool call is in flight the
proxy does not read further client messages (cancellations wait their turn).
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import queue
import subprocess
import sys
import threading
from pathlib import Path

from .gateway import Gateway
from .models import ActionRequest

JSONRPC = "2.0"
CALL_TIMEOUT_SEC = 120


def log(message: str) -> None:
    # stdout is the MCP channel; diagnostics go to stderr only.
    print(f"[agent-firewall] {message}", file=sys.stderr, flush=True)


class ServerConnection:
    """A live MCP server over stdio. One reader thread routes what it says:
    answers to requests the proxy made itself go to the waiting caller, and
    everything else is relayed to the client."""

    def __init__(self, argv: list[str], relay):
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True,
                                     bufsize=1)
        self._relay = relay
        self._pending: dict[str, queue.Queue] = {}
        self._pending_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._ids = itertools.count(1)
        self.closed = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def send(self, message: dict) -> None:
        if self.closed.is_set():
            raise ConnectionError("MCP server has exited")
        with self._write_lock:
            self.proc.stdin.write(json.dumps(message) + "\n")
            self.proc.stdin.flush()

    def request(self, method: str, params: dict,
                timeout: float = CALL_TIMEOUT_SEC) -> dict:
        # Proxy-owned ids never collide with the client's: the answer is routed
        # back here, and the proxy replies to the client under the client's id.
        rid = f"agent-firewall-{next(self._ids)}"
        box: queue.Queue = queue.Queue(maxsize=1)
        with self._pending_lock:
            self._pending[rid] = box
        try:
            self.send({"jsonrpc": JSONRPC, "id": rid, "method": method,
                       "params": params})
            try:
                return box.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError(f"MCP server did not answer {method} "
                                   f"within {timeout:.0f}s") from None
        finally:
            with self._pending_lock:
                self._pending.pop(rid, None)

    def call_tool(self, name: str, arguments: dict) -> dict:
        response = self.request("tools/call", {"name": name,
                                               "arguments": arguments})
        if "error" in response:
            raise RuntimeError(f"server error: {response['error'].get('message')}")
        return response["result"]

    def _read(self) -> None:
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                log(f"ignoring non-JSON output from the server: {line[:120]!r}")
                continue
            is_response = "id" in message and ("result" in message
                                               or "error" in message)
            with self._pending_lock:
                box = self._pending.get(str(message.get("id"))) if is_response else None
            if box is not None:
                box.put(message)
            else:
                self._relay(message)
        self.closed.set()
        with self._pending_lock:
            for box in self._pending.values():
                box.put({"error": {"code": -32000, "message": "MCP server exited"}})
        log("MCP server exited")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class McpProxy:
    def __init__(self, gateway: Gateway, server_name: str,
                 server_argv: list[str], client_in=None, client_out=None):
        self.gateway = gateway
        self.server_name = server_name
        self.client_in = client_in or sys.stdin
        self.client_out = client_out or sys.stdout
        self._out_lock = threading.Lock()
        self.server = ServerConnection(server_argv, relay=self.to_client)
        gateway.executor.mcp_backends[server_name] = self.server

    def to_client(self, message: dict) -> None:
        with self._out_lock:
            self.client_out.write(json.dumps(message) + "\n")
            self.client_out.flush()

    def run(self) -> None:
        try:
            for line in self.client_in:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    self.to_client({"jsonrpc": JSONRPC, "id": None, "error": {
                        "code": -32700, "message": "parse error"}})
                    continue
                self.dispatch(message)
        finally:
            self.server.stop()

    def dispatch(self, message: dict) -> None:
        method = message.get("method")
        is_request = method is not None and "id" in message
        try:
            if is_request and method == "tools/call":
                self.to_client(self.handle_call(message))
            elif is_request and method == "tools/list":
                self.to_client(self.handle_list(message))
            else:
                self.server.send(message)
        except (ConnectionError, TimeoutError, OSError) as e:
            if is_request:
                self.to_client({"jsonrpc": JSONRPC, "id": message["id"], "error": {
                    "code": -32000, "message": f"agent firewall: {e}"}})
            else:
                log(f"could not relay {method or 'response'}: {e}")

    def handle_call(self, message: dict) -> dict:
        params = message.get("params") or {}
        req = ActionRequest(actor="mcp-client", tool="mcp.call", params={
            "server": self.server_name, "tool": params.get("name"),
            "arguments": params.get("arguments", {})})
        record, result = self.gateway.handle_with_result(req)
        if record["outcome"] == "executed":
            return {"jsonrpc": JSONRPC, "id": message["id"], "result": result}
        if record["outcome"] == "error":
            text = f"agent firewall: the tool call failed: {record.get('error')}"
        else:
            text = (f"Blocked by agent firewall ({record['rule_id']}): "
                    f"{record['reason']}")
        return {"jsonrpc": JSONRPC, "id": message["id"], "result": {
            "content": [{"type": "text", "text": text}], "isError": True}}

    def handle_list(self, message: dict) -> dict:
        response = self.server.request("tools/list", message.get("params") or {})
        reply = {"jsonrpc": JSONRPC, "id": message["id"]}
        if "error" in response:
            reply["error"] = response["error"]
            return reply
        result = dict(response.get("result") or {})
        allowed = self.gateway.config.mcp_registry.get(self.server_name, set())
        tools = result.get("tools", [])
        result["tools"] = [t for t in tools if t.get("name") in allowed]
        hidden = sorted(t.get("name") for t in tools if t.get("name") not in allowed)
        if hidden:
            log(f"tools/list: hiding unregistered tools {hidden}")
        reply["result"] = result
        return reply


class DenyApprover:
    """Approval cannot use stdin (it is the MCP channel): deny, and say so."""

    def approve(self, decision) -> bool:
        log(f"approval required for {decision.request.tool} "
            f"{decision.normalized}; no terminal available, denied")
        return False


class TtyApprover:
    """Ask on the controlling terminal, never on the MCP pipes."""

    def approve(self, decision) -> bool:
        try:
            with open("/dev/tty", "r+") as tty:
                tty.write(f"\n=== AGENT FIREWALL: APPROVAL REQUIRED ===\n"
                          f"rule:   {decision.rule_id} ({decision.reason})\n"
                          f"action: {decision.normalized}\napprove? [y/N] ")
                tty.flush()
                return tty.readline().strip().lower() in ("y", "yes")
        except OSError:
            return DenyApprover().approve(decision)


def verify_pins(pins: list[str]) -> None:
    """--pin PATH=SHA256: refuse to launch a server whose code changed."""
    for pin in pins:
        path, _, expected = pin.rpartition("=")
        if not path or not expected:
            raise SystemExit(f"bad --pin {pin!r}: expected PATH=SHA256")
        actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if actual != expected.lower():
            raise SystemExit(f"pin mismatch for {path}: expected {expected}, "
                             f"got {actual}; refusing to start the server")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vt-agent-firewall-mcp",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("--policy", required=True, help="policy JSON file")
    parser.add_argument("--audit", required=True, help="append-only audit JSONL")
    parser.add_argument("--server-name", required=True,
                        help="name of this server in the policy's mcp_registry")
    parser.add_argument("--base-dir", help="resolve relative policy paths here")
    parser.add_argument("--pin", action="append", default=[],
                        help="PATH=SHA256 the server's code must match")
    parser.add_argument("--tty-approval", action="store_true",
                        help="ask for approvals on /dev/tty instead of denying")
    parser.add_argument("server", nargs=argparse.REMAINDER,
                        help="-- followed by the MCP server command")
    args = parser.parse_args(argv)
    server_argv = args.server[1:] if args.server[:1] == ["--"] else args.server
    if not server_argv:
        parser.error("missing the MCP server command after --")
    verify_pins(args.pin)
    approver = TtyApprover() if args.tty_approval else DenyApprover()
    gateway = Gateway(args.policy, args.audit, approver=approver,
                      base_dir=args.base_dir)
    log(f"proxying MCP server {args.server_name!r}: {' '.join(server_argv)}")
    McpProxy(gateway, args.server_name, server_argv).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
