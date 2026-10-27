"""MCP proxy: put the gateway between an MCP client and a real MCP server.

The client (Claude Code, an IDE, any MCP host) launches this proxy as if it were
the server; the proxy launches the real server and relays JSON-RPC over stdio.

- `tools/call` goes through the gateway: policy (registry + path arguments),
  audit, fail-closed. A blocked call never reaches the server; the client gets a
  tool result with `isError: true` that says which rule stopped it. A
  `tools/call` sent as a notification (no id) is dropped, never relayed.
- `tools/list` is filtered: tools that are not in the registry are not even
  shown to the model.
- `resources/read` goes through the gateway too and is denied unless the
  policy lists the server in `mcp_resources`; while denied, resource lists
  come back empty and subscriptions are refused.
- The policy file and the audit log given on the command line join the
  protected paths at startup, as in the agent hook: a call that names either
  is refused (`mcp-protected-path`) before the server sees it.
- Only known MCP methods are relayed (initialize, ping, prompts, completion,
  logging, notifications, and answers to the server's own requests; a policy
  can add more with `mcp_relay_methods`). Anything else is refused, and
  JSON-RPC batches are rejected (MCP 2025-06-18 removed them).
- Server-to-client requests (sampling, roots, elicitation) are relayed to the
  client untouched: the client decides on those.

Approval never reads stdin, because stdin is the MCP channel: an action that
requires approval is denied unless `--tty-approval` is given and a terminal is
available at /dev/tty.

    python -m agent_firewall.mcp_proxy --policy policies/default.json \\
        --audit logs/mcp-audit.jsonl --server-name filesystem \\
        -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir

Learning mode (`--learn TRACE`, agent_firewall/learn.py) appends one
observation per `tools/call` and `resources/read` to TRACE for
`vt-agent-firewall-propose`, written before anything reaches the server. The
policy is still enforced (there is no ask mode here), the trace is added to the
protected paths, and once the trace cannot be opened or written every call is
refused (`fail-closed`) until the proxy restarts, as with the audit log.

Limitation: calls are handled one at a time; while a tool call is in flight the
proxy does not read further client messages (cancellations wait their turn).
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import queue
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from . import learn
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

    def read_resource(self, uri: str) -> dict:
        response = self.request("resources/read", {"uri": uri})
        if "error" in response:
            raise RuntimeError(f"server error: {response['error'].get('message')}")
        return response["result"]

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


def protect_own_files(gateway: Gateway, *paths) -> list[Path]:
    """Add the proxy's own files to the protected paths, resolved the way the
    hook resolves its own (realpath: symlinks and relative paths), and return
    them. A tool call that names one is refused (`mcp-protected-path`)."""
    own = [Path(os.path.realpath(p)) for p in paths if p]
    gateway.config.protected.update(own)
    return own


class Learner:
    """`--learn TRACE`: one observation per gated request, before it executes.

    The proxy is one session (one client, one gateway, one taint flag), so every
    observation carries the same generated session id. The trace joins the
    protected paths before anything is decided. Once it cannot be opened or
    written, every observation fails, so the gateway refuses every allowed call
    from then on: a trace with a torn or missing line is not one to propose from.
    """

    HOST = "mcp-proxy"

    def __init__(self, gateway: Gateway, trace: str | Path, policy: str | Path,
                 server_name: str, self_protected=()):
        """`self_protected`: the proxy's other own files (`protect_own_files`),
        recorded in each observation with the trace."""
        self.gateway = gateway
        self.session_id = f"mcp-{server_name}-{uuid.uuid4().hex[:12]}"
        own = protect_own_files(gateway, trace)
        self.error: str | None = None
        self.writer = None
        try:
            self.writer = learn.TraceWriter(trace, "enforce", gateway.config, policy,
                                            self_protected=[*self_protected, *own])
        except learn.TraceUnavailable as e:
            self._fail(str(e))

    def observer(self, method: str):
        def observe(record: dict) -> None:
            if self.error is not None:
                raise learn.TraceUnavailable(f"learning trace unavailable ({self.error})")
            try:
                self.writer.observe({**record, "host": self.HOST, "host_tool": method,
                                     "session_id": self.session_id},
                                    tainted=self.gateway.session.tainted)
            except Exception as e:
                self._fail(str(e))
                raise
        return observe

    def _fail(self, error: str) -> None:
        self.error = error
        log(f"{error}; refusing every tool call until restarted (fail-closed)")

    def close(self) -> None:
        if self.writer is not None:
            self.writer.close()


class McpProxy:
    def __init__(self, gateway: Gateway, server_name: str,
                 server_argv: list[str], client_in=None, client_out=None,
                 learner: Learner | None = None):
        self.gateway = gateway
        self.server_name = server_name
        self.client_in = client_in or sys.stdin
        self.client_out = client_out or sys.stdout
        self.learner = learner
        self._out_lock = threading.Lock()
        self.server = ServerConnection(server_argv, relay=self.to_client)
        gateway.executor.mcp_backends[server_name] = self.server

    def _observe(self, method: str):
        return self.learner.observer(method) if self.learner is not None else None

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
            if self.learner is not None:
                self.learner.close()

    RELAYED_METHODS = frozenset({
        "initialize", "ping", "prompts/list", "prompts/get", "completion/complete",
        "logging/setLevel",
    })
    GATED_METHODS = frozenset({"tools/call", "resources/read"})
    RESOURCE_METHODS = frozenset({
        "resources/list", "resources/templates/list", "resources/subscribe",
        "resources/unsubscribe",
    })

    def dispatch(self, message) -> None:
        if isinstance(message, list):
            self.to_client({"jsonrpc": JSONRPC, "id": None, "error": {
                "code": -32600,
                "message": "agent firewall: JSON-RPC batches are not supported"}})
            log("rejected a JSON-RPC batch")
            return
        if not isinstance(message, dict):
            self.to_client({"jsonrpc": JSONRPC, "id": None, "error": {
                "code": -32600, "message": "agent firewall: invalid request"}})
            return
        method = message.get("method")
        is_request = method is not None and "id" in message
        try:
            if method is None:
                # An answer to a request the server made (sampling, roots, ...).
                self.server.send(message)
            elif not is_request:
                if method in self.GATED_METHODS:
                    log(f"dropped {method} sent as a notification: it would "
                        f"reach the server without passing the policy")
                elif method.startswith("notifications/") \
                        or method in self.gateway.config.mcp_relay_methods:
                    self.server.send(message)
                else:
                    log(f"dropped unknown notification {method!r}")
            elif method == "tools/call":
                self.to_client(self.handle_call(message))
            elif method == "tools/list":
                self.to_client(self.handle_list(message))
            elif method == "resources/read":
                self.to_client(self.handle_resource_read(message))
            elif method in self.RESOURCE_METHODS:
                self.to_client(self.handle_resource_method(message))
            elif method in self.RELAYED_METHODS \
                    or method in self.gateway.config.mcp_relay_methods:
                self.server.send(message)
            else:
                self.to_client({"jsonrpc": JSONRPC, "id": message["id"], "error": {
                    "code": -32601,
                    "message": f"agent firewall: method {method!r} is not relayed"}})
        except (ConnectionError, TimeoutError, OSError) as e:
            if is_request:
                self.to_client({"jsonrpc": JSONRPC, "id": message["id"], "error": {
                    "code": -32000, "message": f"agent firewall: {e}"}})
            else:
                log(f"could not relay {method or 'response'}: {e}")

    def _resources_enabled(self) -> bool:
        return self.server_name in self.gateway.config.mcp_resources

    def handle_resource_read(self, message: dict) -> dict:
        params = message.get("params") or {}
        req = ActionRequest(actor="mcp-client", tool="mcp.resource", params={
            "server": self.server_name, "uri": params.get("uri")})
        record, result = self.gateway.handle_with_result(
            req, observe=self._observe("resources/read"))
        if record["outcome"] == "executed":
            return {"jsonrpc": JSONRPC, "id": message["id"], "result": result}
        if record["outcome"] == "error":
            text = f"agent firewall: the resource read failed: {record.get('error')}"
        else:
            text = (f"Blocked by agent firewall ({record['rule_id']}): "
                    f"{record['reason']}")
        return {"jsonrpc": JSONRPC, "id": message["id"],
                "error": {"code": -32002, "message": text}}

    def handle_resource_method(self, message: dict) -> dict:
        method = message["method"]
        if self._resources_enabled():
            response = self.server.request(method, message.get("params") or {})
            reply = {"jsonrpc": JSONRPC, "id": message["id"]}
            if "error" in response:
                reply["error"] = response["error"]
            else:
                reply["result"] = response.get("result", {})
            return reply
        if method == "resources/list":
            result = {"resources": []}
        elif method == "resources/templates/list":
            result = {"resourceTemplates": []}
        else:
            return {"jsonrpc": JSONRPC, "id": message["id"], "error": {
                "code": -32002,
                "message": "Blocked by agent firewall (mcp-resources-denied)"}}
        return {"jsonrpc": JSONRPC, "id": message["id"], "result": result}

    def handle_call(self, message: dict) -> dict:
        params = message.get("params") or {}
        req = ActionRequest(actor="mcp-client", tool="mcp.call", params={
            "server": self.server_name, "tool": params.get("name"),
            "arguments": params.get("arguments", {})})
        record, result = self.gateway.handle_with_result(
            req, observe=self._observe("tools/call"))
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
    parser.add_argument("--learn", metavar="TRACE",
                        help="learning mode: also append one observation per "
                             "tools/call and resources/read to TRACE (JSONL) for "
                             "vt-agent-firewall-propose; the policy is still enforced, "
                             "the trace is protected, and a trace that cannot be "
                             "written refuses every call")
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
    # Self-protection, as in the hook: no tool call may read or rewrite the
    # policy that judges the agent or the log that records it.
    own = protect_own_files(gateway, args.policy, args.audit)
    learner = (Learner(gateway, args.learn, args.policy, args.server_name,
                       self_protected=own)
               if args.learn else None)
    log(f"proxying MCP server {args.server_name!r}: {' '.join(server_argv)}")
    McpProxy(gateway, args.server_name, server_argv, learner=learner).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
