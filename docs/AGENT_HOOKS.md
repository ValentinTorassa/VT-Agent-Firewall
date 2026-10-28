# Agent hooks: Claude Code and Codex

The MCP proxy sees MCP tools only. An agent host's built-in tools never pass
through it: Claude Code's `Bash`, `Read`, `Write` and `Edit`, Codex's shell and
`apply_patch`. Those are the tools an agent uses to read secrets and run
commands. Both hosts run a `PreToolUse` hook before every tool call, and
`vt-agent-firewall-hook` is that hook: it puts the same policy engine and the
same audit log in front of the built-in tools.

```text
host tool call (JSON on stdin)
  → translate        Bash → shell.run (run by a shell), Read → fs.read, Write/Edit → fs.write, ...
  → policy           the same PolicyEngine and policy file as the gateway and the MCP proxy
  → audit            one record per decision, fsynced before the host may act
  → answer           deny (JSON + exit 2), ask, or silence; the host runs the tool, never the hook
```

## What each tool becomes

| Host tool | Request | Notes |
|---|---|---|
| `Bash`, `Monitor` with `command` | `shell.run`, `via_shell` | The host gives the line to bash or zsh, so it must first pass `sh-syntax` (below). |
| `Read` | `fs.read` | |
| `Write`, `Edit`, `NotebookEdit`, legacy `MultiEdit` | `fs.write` | Written content is audited as SHA-256 plus length. |
| `WebFetch`, `Monitor` with `ws` | `net.request` | Denied unless the policy's `network.allow` lists the origin (GET only; see the [README](../README.md#narrower-grants)). |
| `mcp__<server>__<tool>` | `mcp.call` | Only if you match MCP tools; they then need an `mcp_registry` entry. |
| Codex `apply_patch` | `fs.write` per file | Every `Add`, `Update`, `Delete` and `Move to` path in the patch. |
| anything else the matcher sends | unknown tool | Default-deny (`unknown-tool`). |

### `sh-syntax`: why Bash is stricter than `shell.run`

The gateway's own executor never uses a shell: it splits a line with `shlex` and
runs the argv, so `;`, `|` and `$(...)` are inert characters. A host's Bash tool
runs the line in a real shell. `cat notes.txt; curl ...` would check as `cat`
with three file operands and then run `curl`. So a `via_shell` request is
accepted only when the shell would split it into exactly the words the policy
checks, with no expansion: one simple command, literal arguments. Pipes,
redirects, `;` `&&` `||`, `$VAR`, `$(...)`, backticks, globs (`*` `?` `[`), braces,
`~`, comments, line breaks and a leading `=` (a zsh expansion) are refused, with
a reason that tells the agent to split the work into separate calls. Quoted text
stays literal: `grep -e 'a|b' notes.txt` is fine.

## Decisions per host

| Policy decision | Claude Code | Codex |
|---|---|---|
| `block` | `permissionDecision: "deny"` on stdout, the reason on stderr, exit 2 | the same; Codex reads exit 2 and stderr |
| `require_approval` | `permissionDecision: "ask"`: Claude Code shows its permission prompt with the firewall's reason, which names the canonical path | denied as `approval-denied`: Codex ignores `ask` from a hook and would run the tool |
| `require_approval` in `bypassPermissions` mode | denied as `approval-denied`: the docs don't promise that a hook's `ask` still prompts in that mode | n/a |
| `allow` | silent, exit 0: Claude Code's own permission rules and prompts still apply | silent, exit 0 |

By default the hook only narrows what the host allows. `--emit-allow` (Claude
Code only) answers an allowed call with an explicit `allow`, which skips Claude
Code's prompt for that call; deny and ask rules in your settings still apply.

`--learn TRACE` also records every decision for `vt-agent-firewall-propose`,
which proposes a policy from what the agent attempted; the policy is still
enforced unless you choose `--learn-mode ask`. For learning, register the same
command for `PostToolUse` as well
([`examples/hooks/claude-code-settings-learn.json`](../examples/hooks/claude-code-settings-learn.json)):
it records which calls ran, so an ask counts only after your yes, and it never
answers the host. See [LEARNING.md](LEARNING.md).

Every decision is a line in the audit log, with `host`, `host_tool`,
`session_id`, `permission_mode` and the host's `tool_use_id` as the
`correlation_id`. An allowed or ask call is recorded with outcome `delegated`
before the hook answers: the host runs the tool, so there is no `executed`
record and no result preview. A malformed event is recorded as `parse-error`
with a digest of the raw input. The policy file, the audit log, the session
taint store next to it, the learning trace and the host settings that install the
hook are added to the protected paths automatically, so the agent can neither
read nor rewrite them through a gated tool
([below](#keeping-the-firewall-out-of-the-agents-reach)).

## Install for Claude Code

1. Install the package and find the absolute path of the hook:

   ```bash
   pip install 'vt-agent-firewall>=0.3.0'
   command -v vt-agent-firewall-hook
   ```

2. Write a policy for the project. [`examples/hooks/agent-firewall.json`](../examples/hooks/agent-firewall.json)
   is a starting point: the project is the sandbox, `.env`, `.claude`, `.codex`,
   `.mcp.json`, `.git/config` and `.git/hooks` are protected (they hold secrets,
   the agent's own settings, or something that runs code), `protected_names`
   covers `.env.local`, `api/.env`, keys and cloud credentials anywhere in the
   project, `secret_files` lists the files whose values may not leave in any
   request, and only `src`, `tests` and `docs` are writable without a prompt.
   Save it as `.claude/agent-firewall.json` in the project and adjust the lists.

3. Add the hook to a settings file. `.claude/settings.json` applies to everyone
   who works on the project, `.claude/settings.local.json` only to you,
   `~/.claude/settings.json` to all your projects, and managed settings to a
   whole organization. [`examples/hooks/claude-code-settings.json`](../examples/hooks/claude-code-settings.json):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash|Monitor|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
           "hooks": [
             {
               "type": "command",
               "command": "vt-agent-firewall-hook --policy \"$CLAUDE_PROJECT_DIR/.claude/agent-firewall.json\" --base-dir \"$CLAUDE_PROJECT_DIR\" --audit \"$HOME/.local/state/vt-agent-firewall/audit.jsonl\"",
               "timeout": 30,
               "statusMessage": "Agent firewall"
             }
           ]
         }
       ]
     }
   }
   ```

   Use the absolute path from step 1 instead of the bare name if the hook is
   installed in a virtualenv or anywhere the hook's shell may not have on its
   `PATH`. Keep the audit log outside the project. `timeout` is in seconds; keep
   it above the hook's own `--deadline` (20 s by default) so the hook denies
   before Claude Code gives up on it. Add `|mcp__.*` to the matcher to put MCP
   tools under the policy's `mcp_registry` as well. To keep the policy itself
   out of the agent's reach, pin it and keep this command outside the project
   ([below](#keeping-the-firewall-out-of-the-agents-reach)).

4. Test it before you rely on it. A hook that cannot start does not block
   anything (see the limits below), so feed it a fake event first:

   ```bash
   cd /path/to/project
   printf '{"hook_event_name":"PreToolUse","session_id":"smoke","tool_use_id":"smoke-1","cwd":"%s","tool_name":"Read","tool_input":{"file_path":"%s/.env"}}' "$PWD" "$PWD" \
     | vt-agent-firewall-hook --policy .claude/agent-firewall.json --base-dir . --audit /tmp/firewall-smoke.jsonl
   echo "exit=$?"   # expect a deny with (fs-protected) and exit=2
   ```

   Then open `/hooks` in Claude Code to check the hook is registered, and watch
   the first tool calls: a `PreToolUse hook error` notice means the hook did not
   run and the gate is off.

## Install for Codex

Codex has the same `PreToolUse` event ([docs](https://developers.openai.com/codex/hooks)),
configured in `hooks.json` or inline in `config.toml`, in `~/.codex/` or in the
repository's `.codex/`. [`examples/hooks/codex-config.toml`](../examples/hooks/codex-config.toml):

```toml
[[hooks.PreToolUse]]
matcher = "^(Bash|apply_patch)$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'vt-agent-firewall-hook --host codex --policy "$(git rev-parse --show-toplevel)/.codex/agent-firewall.json" --base-dir "$(git rev-parse --show-toplevel)" --audit "$HOME/.local/state/vt-agent-firewall/codex-audit.jsonl"'
timeout = 30
statusMessage = "Agent firewall"
```

Codex skips a new or changed hook until you trust it in `/hooks`: until then
nothing is enforced. Codex's `Bash` covers both the shell tool and unified exec
(`exec_command`). Add `mcp__.*` to the matcher regex for MCP tools.

## Keeping the firewall out of the agent's reach

If the agent can change the policy, the policy is a suggestion. The hook does
three things about that; the rest depends on where you install it.

- **Its own files are protected paths**, whether they exist or not: the policy,
  the audit log, the session taint store next to it (`<audit>.tainted`), the
  learning trace, and the host settings that load the hook.

  | Host | Under `--base-dir` and the sandbox root | User level |
  |---|---|---|
  | Claude Code | `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json` (also under `CLAUDE_PROJECT_DIR`) | `~/.claude/settings.json` and `settings.local.json` next to it (under `CLAUDE_CONFIG_DIR` when set), `~/.claude.json` |
  | Codex | `.codex/config.toml`, `.codex/hooks.json` | `config.toml` and `hooks.json` in `~/.codex` (or `CODEX_HOME`) |

  A gated tool that names one is refused and taints the session: a `Write` of
  `.claude/settings.local.json` with `{"disableAllHooks": true}`, an `Edit` that
  points `--policy` at another file, a `.mcp.json` server that skips the proxy,
  a Codex patch to `.codex/hooks.json`. `--protect PATH` (repeatable) adds
  anything else your setup depends on: a wrapper script, or the virtualenv the
  hook runs from when it lives inside the project.
- **The policy can be pinned.** With `--policy-sha256 HEX` the hook refuses a
  policy file whose SHA-256 is not that one: every call is denied
  (`fail-closed`, audited with both digests) until a human reviews the file and
  pins the new digest. That covers a policy changed by a route the hook does not
  see: an allowed `git checkout` or `git pull` that brings another
  `.claude/agent-firewall.json`, a test runner on `shell_exact` that writes it, a
  tool you did not match, a process outside the agent.

  ```bash
  sha256sum .claude/agent-firewall.json      # macOS: shasum -a 256
  ```

  ```json
  "command": "vt-agent-firewall-hook --policy \"$CLAUDE_PROJECT_DIR/.claude/agent-firewall.json\" --policy-sha256 <digest> --base-dir \"$CLAUDE_PROJECT_DIR\" --audit \"$HOME/.local/state/vt-agent-firewall/audit.jsonl\""
  ```

  A pin is as safe as the file that holds it: put this command in settings the
  project cannot change, `~/.claude/settings.json` (outside the sandbox, and
  protected by the hook) or managed settings with `allowManagedHooksOnly`.
  Pin again after each change you make to the policy, including a learning-mode
  proposal you accept. The MCP proxy takes the same flag and refuses to start.
- **A session's taint outlives the call.** Each hook call is a new process, so
  the hook keeps the ids of tainted sessions in `<audit>.tainted`. Once a
  session names or reaches a protected path, or carries a secret value, its
  later calls get no network, `shell_ask` or `shell_exact`, as in the gateway.
  A store that cannot be read taints every session; one that cannot be opened
  or written denies. Another `session_id` starts clean.

## What it blocks with the example rules

| Tool call | Answer |
|---|---|
| `Read .env`, `Edit` through a symlink to `.env` | deny `fs-protected` |
| `Read .env.local`, `Bash: cat api/.env` (names the list does not spell out) | deny `fs-protected` / `sh-paths` (`protected_names`) |
| `WebFetch` or `Bash: curl ...` with a value from `.env` in the URL or an argument, raw or encoded | deny `secret-egress` |
| `Write .claude/settings.local.json` (`disableAllHooks`), `Edit .claude/settings.json` | deny `fs-protected` |
| a fetch to an allowed origin later in a session that tried `Read .env` | deny `taint-session` |
| any call once the pinned policy file changed (`--policy-sha256`) | deny `fail-closed` |
| `Write` outside the project | deny `fs-sandbox` |
| `Write src/app.py` | silent (allowed) |
| `Write README.md` (inside the project, outside `writable_dirs`) | ask `fs-write-scope` (Codex: deny) |
| `Bash: cat .env`, `head --lines=5 .env` | deny `sh-paths` |
| `Bash: grep -r KEY .` (reaches `.env` without naming it) | deny `sh-recursive` |
| `Bash: grep -f .env src` (a file-valued option) | deny `sh-paths` |
| `Bash: find . -name x -exec sh -c ...` | deny `sh-args` |
| `Bash: curl ...`, `python3 ...`, `cd x` | deny `sh-allowlist` (ask `sh-ask` with the binary on `shell_ask`; Codex: deny) |
| `Bash: cat notes.txt \| head`, `cat $(echo .env)`, `cat .e*` | deny `sh-syntax` |
| `WebFetch`, `Monitor` on a WebSocket | deny `net-deny-all` |
| a tool in the matcher with no mapping | deny `unknown-tool` |
| Codex `apply_patch` adding `.env` | deny `fs-protected` |

Claude Code's own permission rules cover named files but, in their own words,
not "a command that reads files without naming them, such as `grep -r pattern .`".
The firewall walks the tree for those, checks option values, resolves symlinks,
refuses unknown options and keeps an audit trail.

## The protocol this relies on

Checked on 2026-10-03 against [code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks)
and [developers.openai.com/codex/hooks](https://developers.openai.com/codex/hooks)
(plus the Codex hook schemas in `codex-rs/hooks/schema/generated`).

Claude Code:

- The event arrives on stdin with `session_id`, `cwd`, `permission_mode`,
  `hook_event_name: "PreToolUse"`, `tool_name`, `tool_input` and `tool_use_id`.
  `cwd` follows Claude's `cd`. `Write`, `Edit` and `Read` always carry an
  absolute `file_path`.
- `hookSpecificOutput.permissionDecision` is `allow`, `deny`, `ask` or `defer`,
  with `permissionDecisionReason` (shown to Claude for `deny`, to the user for
  `ask`). Several hooks resolve as deny > defer > ask > allow.
- Exit 2 blocks even if JSON says `allow`; the JSON reason is used, else stderr.
  Any other non-zero exit is a non-blocking error and the tool runs. A hook
  that times out, or whose command cannot start (exit 127), does not block.
- A hook's `allow` does not override deny or ask rules in settings.
- `PostToolUse` (checked 2026-10-26) carries the same fields plus
  `tool_response`, and fires only after a tool call completed: not for one
  refused at the prompt (`PostToolUseFailure` covers a call that failed). Exit
  2, a `decision`, `additionalContext` or `updatedToolOutput` there reach the
  model, so the hook uses none of them; another non-zero exit shows the user a
  hook error and changes nothing.
- `matcher` with only letters, digits, `_`, `-`, spaces, `,` and `|` is an exact
  list of tool names; anything else is an unanchored regular expression. `timeout` is in
  seconds and defaults to 600.

Codex:

- Same event name and fields plus `turn_id` and `model`. `Bash` (shell and
  unified exec) and `apply_patch` put a string in `tool_input.command`; MCP and
  other local tools send their arguments.
- A deny is `permissionDecision: "deny"` with a non-empty reason, or exit 2
  with the reason on stderr. JSON is read on exit 0 only.
- `ask`, and `allow` without `updatedInput`, are unsupported: Codex marks the
  hook run failed and lets the tool run. Hence silence for allow and a deny for
  approval.
- Hosted tools such as web search do not go through hooks, and in Codex's own
  words: "Treat tool hooks as a useful guardrail, not a complete enforcement
  boundary."

## Limits

These are the boundaries of a hook, stated plainly:

- **Policy, not isolation.** The hook decides whether a call may start. It does
  not contain what an allowed program does once it runs: allowlist an
  interpreter (`python3`, `node`, `bash`) and the agent can run anything. There
  is no OS sandbox; combine the hook with Claude Code's sandbox, a container or
  a VM for that.
- **Whoever controls the settings controls the hook.** The user can remove it,
  `disableAllHooks` turns every hook off (for a single run too, through
  `--settings`), and a committed `.claude/settings.json` can be edited by anyone
  with commit access.
  The hook keeps the settings files away from the agent's gated tools
  ([above](#keeping-the-firewall-out-of-the-agents-reach)), but a tool you did
  not match, or a process outside the agent, can still edit them: pin the
  policy and keep the hook command where the project cannot reach. For
  enforcement, deploy the hook in managed settings with
  `allowManagedHooksOnly`; Claude Code also lets an installed mod approve a call
  a hook blocked unless the hook comes from managed settings.
- **The host fails open around it.** A timeout, a missing or mistyped command
  (exit 127), or a crash before Python starts lets the tool run. The hook's own
  deadline and its catch-all deny cover everything after it starts, not before.
  Test it (step 4) and watch for `hook error` notices.
- **Bash parsing is deliberately narrow.** Only simple commands pass. The
  binary name is checked, but aliases and shell functions (Claude Code loads
  them from your shell startup files) and `PATH` decide what actually runs under
  that name. The argument grammars follow GNU userland.
- **Codex commands may run elsewhere.** The hook gets the session `cwd`, not the
  `workdir` a Codex command may set, so relative paths can resolve differently
  from where the command runs. `write_stdin` to a running exec session does not
  run `PreToolUse` again.
- **Only matched tools are seen.** Tools without a mapping are denied when they
  reach the hook and invisible when they do not. `Grep`, `Glob` and `LSP` read
  files; `WebSearch`, `Artifact`, `SendUserFile`, `PushNotification` and
  `RemoteTrigger` send data out. Deny the ones you do not use with Claude Code
  permission rules. Files you attach with `@` are inserted without any tool call.
- **Taint follows the host's session id.** It carries from one hook call to the
  next through `<audit>.tainted`, but a call without a `session_id` is decided on
  its own, a new session starts clean, and hooks with different audit logs keep
  different stores. A secret that reached the agent without a protected path
  being named (an approved interpreter, a tool you did not match) does not taint
  the session; only `secret_files` values are recognized when they go out.
- **The audit records the request for approval, not the answer.** The human's
  choice in the host's prompt never reaches the audit log. In learning mode the
  trace's `ran` records (`PostToolUse`) show which calls ran
  ([LEARNING.md](LEARNING.md#why-posttooluse)).
- **Check and use are separate.** The host runs the tool after the hook
  answers; a symlink swapped in between is not seen (TOCTOU).
- **Linux and macOS only.** The PowerShell tool is not parsed: matched, it is
  denied.
