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
 MCP server results, tools/list     │ audit log (outside the sandbox), executor
```

Spelled parameters never cross the boundary: the executor only receives what the
normalizer produced and the policy approved.

## Attacker capabilities considered

1. Indirect prompt injection through any content the agent reads.
2. Path tricks: `..`, absolute paths, symlinks, relative `cwd`.
3. Shell tricks: metacharacters, pipes, subshells, dangerous flags (`find -exec`).
4. Exfiltration over the network, including loopback.
5. Calling tools or MCP servers that were never registered.
6. Social engineering of the approver through the agent's own description of an action.
7. Breaking the audit trail so that actions happen unrecorded.

## Mapping to OWASP

Status: **Implemented** (covered by tests or the demo), **Partial**, **Planned**
(next milestone), **Out of scope**.

### OWASP Top 10 for LLM Applications (2025)

| Risk | How the gateway addresses it | Status |
|---|---|---|
| LLM01 Prompt Injection | Containment, not detection: default-deny policy, protected paths, network deny, taint. The demo is an indirect injection. | Implemented (containment) |
| LLM02 Sensitive Information Disclosure | Protected paths blocked after `realpath`; touching one taints the session and blocks every network action afterwards. | Partial (path-level taint) |
| LLM03 Supply Chain | MCP registry (unlisted tools are hidden and blocked) and `--pin PATH=SHA256` for the server's code. | Partial |
| LLM05 Improper Output Handling | Model output never reaches a shell: `shlex` to argv, `shell=False`, executor sees normalized params only. | Implemented |
| LLM06 Excessive Agency | Default-deny per tool, shell allowlist and forbidden args, approval for out-of-scope writes, per-call tokens scoped to one audience and operation. | Implemented |
| LLM10 Unbounded Consumption | Read cap (64 KB), shell and network timeouts. No rate limiting. | Partial |
| LLM04, LLM07, LLM08, LLM09 | Model-side risks (poisoning, system prompt leakage, embeddings, misinformation). | Out of scope |

### OWASP Top 10 for Agentic Applications (2026)

| Risk | How the gateway addresses it | Status |
|---|---|---|
| ASI01 Agent Goal Hijack | Same containment as LLM01: a hijacked goal still has to pass the policy. | Implemented (containment) |
| ASI02 Tool Misuse and Exploitation | Every tool call is a typed request with per-tool checks; unknown tools are denied. | Implemented |
| ASI03 Identity and Privilege Abuse | Token broker: short-lived tokens scoped per call and audience, the agent never holds a refresh token, and the audit record ties each call to user, agent and token `jti`. Not sender-constrained yet (no DPoP). | Implemented |
| ASI04 Agentic Supply Chain Vulnerabilities | The MCP proxy hides and blocks unregistered tools and can refuse to start a server whose code does not match a pinned SHA-256. No signature verification of packages. | Partial |
| ASI05 Unexpected Code Execution | Shell allowlist, forbidden arguments, argv path checks, `shell=False`. | Implemented |
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
- Allowed actions are audited after execution; a crash in between leaves them unrecorded.
- No TOCTOU protection between normalization and execution.
- Access tokens are bearer tokens (no DPoP): a stolen one works until it expires (5 minutes).
