# Threat model

## What is being protected

The machine and accounts an AI agent operates on behalf of a person: files outside
the task, secrets (`.env`, credentials, tokens), the network as an exfiltration
channel, and the tools the agent can reach (shell, MCP servers, APIs).

## The core assumption

**The model is already compromised.** Anything the agent reads (a README, an issue,
a web page, a tool result) may contain instructions, and the model may follow them.
The gateway does not try to detect prompt injection; it limits what a hijacked
agent can do and records every attempt. Detection is a bonus layer; containment is
the one this project owns.

## Trust boundaries

```text
 untrusted                          │ trusted
 ───────────────────────────────────┼──────────────────────────────────────────
 model output, spelled params,      │ normalized params, policy file,
 content the agent reads,           │ human approval on the terminal,
 MCP server results, tools/list,    │ audit log (outside the sandbox), executor,
 host tool calls (hook stdin)       │ the host's settings that install the hook
```

Spelled parameters never cross the boundary: the executor only receives what the
normalizer produced and the policy approved. With the agent hook the host, not the
executor, runs the tool, so the guarantee is weaker: the hook can only refuse what
it cannot vouch for, and it trusts the host to honor the answer and to keep the
hook installed (see [docs/AGENT_HOOKS.md](AGENT_HOOKS.md#limits)).

## Attacker capabilities considered

1. Indirect prompt injection through any content the agent reads.
2. Path tricks: `..`, absolute paths, symlinks, relative `cwd`.
3. Shell tricks: metacharacters, pipes, subshells, dangerous flags (`find -exec`,
   `find -fprint`), file-valued options (`grep --file=.env`), and recursive reads
   that reach a secret without naming it (`grep -r '' .`, a symlinked directory).
4. Exfiltration over the network, including loopback.
5. Calling tools or MCP servers that were never registered.
6. Social engineering of the approver through the agent's own description of an action.
7. Breaking the audit trail so that actions happen unrecorded.
8. Protocol tricks against the MCP proxy: path arguments under any name, paths
   outside the sandbox, `resources/read`, JSON-RPC batches, and `tools/call` sent
   as a notification.
9. Host shell tricks against the agent hook: a line that an agent host's Bash tool
   hands to a real shell, where `;`, pipes, redirects, `$(...)`, variables, globs,
   braces and `~` would change what runs after the argv was checked; patches that
   name files under a misleading spelling; and malformed hook input meant to make
   the hook crash (a crash would let the host run the tool).

## Mapping to OWASP

Status: **Implemented** (covered by tests or the demo), **Partial**, **Planned**
(next milestone), **Out of scope**.

### OWASP Top 10 for LLM Applications (2025)

| Risk | How the gateway addresses it | Status |
|---|---|---|
| LLM01 Prompt Injection | Containment, not detection: default-deny policy, protected paths, network deny, taint. The demo is an indirect injection. | Implemented (containment) |
| LLM02 Sensitive Information Disclosure | Protected paths, and everything under them, blocked after `realpath`: named directly, through an option value, or reached by a recursive walk (symlinks followed). Naming or reaching one, blocked or not, taints the session, and every network and API action is blocked afterwards. | Partial (path-level taint) |
| LLM03 Supply Chain | MCP registry (unlisted tools are hidden and blocked) and `--pin PATH=SHA256` for the server's code. | Partial |
| LLM05 Improper Output Handling | Model output never reaches a shell: `shlex` to argv, `shell=False`, executor sees normalized params only. | Implemented |
| LLM06 Excessive Agency | Default-deny per tool, shell allowlist with a per-binary argument grammar, approval for out-of-scope writes, per-call tokens scoped to one audience and operation. | Implemented |
| LLM10 Unbounded Consumption | Read cap (64 KB), shell and network timeouts. No rate limiting. | Partial |
| LLM04, LLM07, LLM08, LLM09 | Model-side risks (poisoning, system prompt leakage, embeddings, misinformation). | Out of scope |

### OWASP Top 10 for Agentic Applications (2026)

| Risk | How the gateway addresses it | Status |
|---|---|---|
| ASI01 Agent Goal Hijack | Same containment as LLM01: a hijacked goal still has to pass the policy. | Implemented (containment) |
| ASI02 Tool Misuse and Exploitation | Every tool call is a typed request with per-tool checks; unknown tools are denied. The agent hook applies the same checks to Claude Code's and Codex's built-in tools before the host runs them. | Implemented (hook: Partial, see limitations) |
| ASI03 Identity and Privilege Abuse | Token broker: short-lived tokens scoped per call and audience, the agent never holds a refresh token, and the audit record ties each call to user, agent and token `jti`. Not sender-constrained yet (no DPoP). | Implemented |
| ASI04 Agentic Supply Chain Vulnerabilities | The MCP proxy hides and blocks unregistered tools, checks every path-like argument, denies resources by default, relays only known methods, and can refuse to start a server whose code does not match a pinned SHA-256 (at launch only). No signature verification of packages. | Partial |
| ASI05 Unexpected Code Execution | Shell allowlist; each allowlisted binary has an argument grammar, so unknown options are refused and `find` only accepts allowlisted predicates (no `-exec`, `-ok`, `-fprint`, `-delete`); argv, option-value and recursive-walk path checks; `shell=False`, stdin from `/dev/null`. A line a host shell will run (`via_shell`) must be one simple command with nothing to expand (`sh-syntax`). Every bypass found in review is a regression test and a corpus case. | Implemented (GNU userland; see limitations) |
| ASI06 Memory and Context Poisoning | The gateway keeps no agent memory. | Out of scope |
| ASI07 Insecure Inter-Agent Communication | Single agent only. | Out of scope |
| ASI08 Cascading Failures | Fail-closed: a parser error denies; an audit failure poisons the gateway and denies everything afterwards. | Partial |
| ASI09 Human-Agent Trust Exploitation | The approval prompt shows the normalized action, never the agent's description; timeout or non-interactive stdin denies. | Implemented |
| ASI10 Rogue Agents | Append-only audit of every decision; no behavioral detection. | Partial |

## Delegated credentials: the four failure modes

The OAuth layer targets the ways delegation breaks when the caller is an agent:

1. **Scope that stays open.** A token granted for one task keeps working for every
   later task. The broker issues per-tool, per-audience tokens that expire in minutes.
2. **Refresh token as permanent access.** Whoever holds the refresh token holds the
   account. The refresh token stays in the broker; the agent only receives access tokens.
3. **Authentication mistaken for authorization.** Knowing *who* the agent acts for
   does not decide *what* it may do. Every call is still evaluated by the policy.
4. **Confused deputy.** A tool with its own broad credential performs an action the
   agent itself was not allowed to request. Tokens are exchanged for the specific
   audience and scope of the call, never forwarded as-is.

Each one is a pair of tests in `tests/test_delegation.py`: the naive pattern where the
attack works, and the same attack stopped by the gateway and the broker.

## Known limitations

- No OS-level sandbox: code executed outside the pipeline bypasses it.
- Taint is per path, not per content: an allowed read pasted into an allowed channel
  is not detected.
- Allowed actions get a durable intent record before execution and an outcome
  after. A crash in between leaves an unresolved intent: the record alone cannot
  prove whether the external action happened, and nothing reconciles it yet.
- The argument grammars follow GNU coreutils, grep and findutils. On a system whose
  binaries parse options differently (BSD userland on macOS), an option can mean
  something the grammar does not expect. Binaries added to the allowlist without a
  grammar get a conservative fallback (every operand and `--opt=value` value is a
  path; `-r`/`-R` means recursive), not a precise parse.
- Recursive walks are checked by walking the tree before the command runs; a tree
  can change between the check and the run (TOCTOU), and trees over 20,000 entries
  are refused instead of verified.
- Outside the named path arguments, MCP path detection is a heuristic (absolute,
  `./`, `../`, `~`, `file:`, a slash without spaces, or a name that exists under the
  server's root). It over-blocks free text that looks like a path; a relative name
  that does not exist yet and has no slash is not treated as a path.
- A tainted session still reaches registered MCP tools; the taint blocks the
  network and `api.call`.
- Server-to-client MCP requests (sampling, roots, elicitation) and `prompts/*` are
  relayed untouched: the client decides on them.
- `--pin` checks the server's code at launch only; a server fetched at run time
  (`npx -y`) can change after the check.
- No TOCTOU protection between normalization and execution.
- Access tokens are bearer tokens (no DPoP): a stolen one works until it expires (5 minutes).
- The agent hook is a policy check, not isolation: an allowed binary runs with the
  host's full rights. Whoever controls the host's settings can remove or disable
  it, and the host runs the tool when the hook times out or cannot start; only the
  hook's own failures after it starts are fail-closed. Aliases, shell functions and
  `PATH` decide what an allowlisted name runs. Codex gives the hook the session
  `cwd`, not a command's `workdir`. Each hook call is its own session, so taint does
  not carry across calls, and the audit records a request for approval, not the
  human's answer. Details: [docs/AGENT_HOOKS.md](AGENT_HOOKS.md#limits).
