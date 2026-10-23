# Changelog

## 0.3.0 — 2026-10-23

Learning mode: observe a real session, then propose a policy instead of writing
one from scratch.

- **Recording (`vt-agent-firewall-hook --learn TRACE`):** one observation per
  request in a JSONL trace (the normalized action, the policy's decision, the
  session, and provenance: sandbox root, a digest of the policy file, the hook's
  own protected files). Written content stays a digest, as in the audit log. The
  trace is added to the protected paths, and a trace that cannot be written denies
  (`fail-closed`).
- **Two modes:** `--learn-mode enforce` (default) answers exactly as without
  `--learn`. `--learn-mode ask` (Claude Code only) turns a refusal by
  `sh-allowlist` or `mcp-unknown-tool` into Claude Code's prompt (`learn-ask`)
  when the call passes every other check with that grant; every other refusal
  stays a denial, and a session that named or reached a protected path is not
  asked again. Audited as `require_approval` with the original rule in
  `rules_matched`.
- **Proposals (`vt-agent-firewall-propose`, `agent_firewall/learn.py`):** replays
  the traces against the policy and writes a proposed policy and a report: each
  grant with how often it was seen, in how many sessions, and examples. It only
  proposes writable directories (the first one under the sandbox root, never the
  root or a hidden directory) and binaries with an argument grammar. Binaries
  without one (interpreters, network clients, binaries that write), MCP tools and
  files in the root are listed for a human decision; protected paths, the
  sandbox, network and forbidden arguments are copied unchanged. Observations
  after a session's protected-path access and refusals at approval are not
  learned from. The proposal is replayed against every observation and refused
  if any other decision got looser; it is never written over the policy.
  `--drop-unused` also removes allowlisted binaries and writable directories no
  observation used.
- `Gateway.decide(relax=...)` lets a caller turn a decision into an
  approval-gated one before it is audited (never into an allow), and
  `Config.from_raw` builds a config from a parsed policy.
- Docs: `docs/LEARNING.md` (modes, what is and is not proposed, a walkthrough on
  `demo_workspace` with `scripts/run_learning_demo.py`, limits); README and
  README.es.
- Tests: `tests/test_learn.py` (recording, ask mode, proposals, the CLI, and the
  whole attack corpus learned case by case without a single grant).

## 0.2.0 — 2026-10-04

The policy now reaches an agent host's built-in tools, not only MCP tools.

- **Agent hook (`vt-agent-firewall-hook`, `agent_firewall/hook.py`):** a
  `PreToolUse` hook for Claude Code and Codex. `Bash` and `Monitor` become
  `shell.run`, `Read` becomes `fs.read`, `Write`/`Edit`/`MultiEdit`/`NotebookEdit`
  become `fs.write`, `WebFetch` and WebSocket monitors become `net.request`,
  `mcp__<server>__<tool>` becomes `mcp.call`, and a Codex `apply_patch` becomes one
  `fs.write` per file it touches; any other tool is denied (`unknown-tool`).
  `block` answers deny (JSON on stdout and exit 2 with the reason on stderr),
  `require_approval` answers Claude Code's `ask` (denied on Codex, which ignores
  `ask` from a hook, and in Claude Code's `bypassPermissions` mode), and `allow`
  stays silent so the host's own permission rules still apply (`--emit-allow` for
  an explicit allow on Claude Code).
- **Fail-closed hook:** malformed input, an unmapped tool, an unreadable policy, an
  unavailable audit log, an internal error and the hook's own deadline
  (`--deadline`, 20 s, below the host timeout) all deny with exit 2, the only exit
  code both hosts treat as a block. The policy file and the audit log are added to
  the protected paths, so the agent can neither read nor rewrite them.
- **`sh-syntax` (`agent_firewall/shell_syntax.py`):** a `shell.run` request marked
  `via_shell`, because a host will hand the line to bash or zsh, must be one simple
  command with nothing for the shell to expand. `cat notes.txt; curl ...`,
  `cat .e*`, `cat $(echo .env)` and redirects used to look like `cat` with odd
  file names. A refused line that names a protected path still taints the session.
- **Audit without execution:** `Gateway.decide()` runs the policy and records the
  decision without executing; an allowed call gets a fsynced `delegated` record
  before the host may act. `Gateway.refuse()` records input that could not become
  a request (`parse-error`, with a digest of the raw input). Hook records carry
  `host`, `host_tool`, `session_id`, `permission_mode` and the host's `tool_use_id`
  as `correlation_id`.
- **Audit writes are locked:** each record is written under an exclusive advisory
  lock (POSIX), so parallel hook processes appending to one log keep every record
  on its own line.
- Docs: `docs/AGENT_HOOKS.md` (install for both hosts, a smoke test, what it blocks,
  the protocol details it relies on, its limits), with examples in
  `examples/hooks/`. README, README.es and the threat model cover the hook.
- Tests: `tests/test_hook.py` (deny, ask, allow, malformed input, fail-closed paths,
  audit records, Codex patches, a real subprocess run). The corpus has 26 cases;
  the five new ones are lines a host shell would expand.
- CI checks the `vt-agent-firewall-hook` entry point.

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
