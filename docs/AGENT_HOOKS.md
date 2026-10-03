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
| `WebFetch`, `Monitor` with `ws` | `net.request` | Network is deny-all, so these are always denied. |
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

Every decision is a line in the audit log, with `host`, `host_tool`,
`session_id`, `permission_mode` and the host's `tool_use_id` as the
`correlation_id`. An allowed or ask call is recorded with outcome `delegated`
before the hook answers: the host runs the tool, so there is no `executed`
record and no result preview. A malformed event is recorded as `parse-error`
with a digest of the raw input. The policy file and the audit log passed on the
command line are added to the protected paths automatically, so the agent can
neither read nor rewrite them through a gated tool.

## Install for Claude Code

1. Install the package and find the absolute path of the hook:

   ```bash
   pip install 'vt-agent-firewall>=0.2.0'
   command -v vt-agent-firewall-hook
   ```

2. Write a policy for the project. [`examples/hooks/agent-firewall.json`](../examples/hooks/agent-firewall.json)
   is a starting point: the project is the sandbox, `.env`, `.claude`, `.codex`,
   `.mcp.json`, `.git/config` and `.git/hooks` are protected (they hold secrets,
   the agent's own settings, or something that runs code), and only `src`,
   `tests` and `docs` are writable without a prompt. Save it as
   `.claude/agent-firewall.json` in the project and adjust the lists.

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
   tools under the policy's `mcp_registry` as well.

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

## What it blocks with the example rules

| Tool call | Answer |
|---|---|
| `Read .env`, `Edit` through a symlink to `.env` | deny `fs-protected` |
| `Write` outside the project | deny `fs-sandbox` |
| `Write src/app.py` | silent (allowed) |
| `Write README.md` (inside the project, outside `writable_dirs`) | ask `fs-write-scope` (Codex: deny) |
| `Bash: cat .env`, `head --lines=5 .env` | deny `sh-paths` |
| `Bash: grep -r KEY .` (reaches `.env` without naming it) | deny `sh-recursive` |
| `Bash: grep -f .env src` (a file-valued option) | deny `sh-paths` |
| `Bash: find . -name x -exec sh -c ...` | deny `sh-args` |
| `Bash: curl ...`, `python3 ...`, `cd x` | deny `sh-allowlist` |
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
  The agent cannot edit the settings through a gated tool when `.claude` is
  protected, but a tool you did not match, or a process outside the agent, can.
  For enforcement, deploy the hook in managed settings with
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
- **Each call is its own session.** Taint does not carry from one hook call to
  the next. With network deny-all every network call is blocked anyway.
- **The audit records the request for approval, not the answer.** The human's
  choice in the host's prompt never reaches the hook.
- **Check and use are separate.** The host runs the tool after the hook
  answers; a symlink swapped in between is not seen (TOCTOU).
- **Linux and macOS only.** The PowerShell tool is not parsed: matched, it is
  denied.
