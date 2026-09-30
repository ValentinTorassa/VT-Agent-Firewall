# Changelog

## 0.1.1 — 2026-09-30

Closes the bypasses found in the 2026-09-29 review. Every one is a regression test
(`tests/test_bypasses.py`, `tests/test_mcp_proxy.py`) and a corpus case.

- **Protected paths cover everything under them.** Entries used to match exactly, so
  a file inside a protected directory could be read.
- **Shell arguments follow a grammar per binary** (`agent_firewall/argv.py`) instead
  of "every non-flag token is a path". Option values are path-checked
  (`grep --file=.env`, `-f.env`, `--exclude-from=`, `find -newer`), and options the
  grammar does not know are refused (`sh-args`), e.g. `wc --files0-from=`.
- **Recursive walks are checked (`sh-recursive`).** `grep -r '' .` named no protected
  file and dumped `.env`; `grep -R` through a symlinked directory, `grep -d recurse`,
  `ls -R` and `find` without a bounding `-maxdepth` did the same. The gateway now
  walks the tree, symlinks followed, and blocks when it reaches a protected path or
  leaves the sandbox.
- **`find` predicates are an allowlist.** `-fprint` overwrote a file without
  approval; `-fprint0`, `-fprintf`, `-fls`, `-ok`, `-okdir` were also open.
- **Taint on potential access.** Naming or reaching a protected path taints the
  session even when that request is blocked for another reason.
- **MCP proxy:** every path-like argument is checked, under any name and nested,
  and paths outside the sandbox are blocked (`mcp-sandbox`); relative paths can
  resolve against the server's root (`mcp_roots`). `resources/read` goes through the
  policy and is denied by default (`mcp-resources-denied`). Only known methods are
  relayed, JSON-RPC batches are rejected (they used to crash the proxy), and a
  `tools/call` sent as a notification is dropped instead of relayed.
- **Executor:** shell commands get `/dev/null` as stdin, so `grep foo` with no file
  cannot read the proxy's JSON-RPC channel.
- **Audit minimization:** written content is recorded as SHA-256 plus length and
  network bodies as a 64-character preview plus digest; `audit_verbose` keeps the
  full values for debugging.
- `tests/test_model_following.py` is plain unittest, so CI runs it (it imported
  pytest, which CI does not install, and the release workflow failed with it).
- Docs: the threat model and README no longer say allowed actions are audited after
  execution, the corpus count is right (21 cases), and the limitations name what is
  still open.

## 0.1.0 — 2026-09-24

First public release, the reference implementation for the talk *"Dónde se rompe
OAuth cuando el que llama es un agente"* (OWASP Village, Ekoparty 2026).

- **Gateway pipeline:** normalize → default-deny policy → human approval → append-only
  audit → executor, fail-closed when parsing fails or the audit store is unavailable.
- **Delegated credentials (`api.call`):** a token broker holds the user's grant and
  refresh token; each allowed call gets its own token for one audience and one scope,
  valid five minutes, with the agent as actor. The policy decides each operation
  before any token exists. Revocation kills live tokens.
- **The four OAuth failure modes** as paired tests (`tests/test_delegation.py`):
  the naive pattern where the attack works, and the same attack stopped.
- **MCP proxy** (`vt-agent-firewall-mcp`): the gateway in front of any stdio MCP
  server. Filters `tools/list`, checks path arguments, blocks unregistered tools,
  pins the server's code by SHA-256. Checked against
  `@modelcontextprotocol/server-filesystem` 0.2.0.
- Threat model mapped to the OWASP Top 10 for LLM Applications (2025) and the OWASP
  Top 10 for Agentic Applications (2026).
- Apache-2.0. Standard library only, Python 3.11+.
