"""Is a command line one simple command with nothing for a shell to expand?

The gateway's own executor never uses a shell: `shell.run` splits the line with
shlex and executes the argv. An agent host's Bash tool (Claude Code, Codex)
hands the same string to bash or zsh instead, and a shell does much more than
split words. It chains commands (`;`, `&&`, `|`), redirects (`>`, `<`),
substitutes (`$(...)`, backticks, `$VAR`) and expands globs, braces and `~`. A
line checked as argv but run by a shell can do something else entirely:
`cat notes.txt; curl ...` checks as `cat` with three file operands.

`problem()` returns None only when bash and zsh (default options) would split
the line into exactly the words `shlex.split` gives, with no expansion, so the
argv the policy checks is the argv that runs. Anything else is refused,
including text inside double quotes that the shell still expands (`$`, backticks).
This is deliberately narrower than shell grammar: a compound command, a pipe or
a redirect has to become separate, simple tool calls.
"""

from __future__ import annotations

# Unquoted, each of these is an operator, an expansion, a glob, grouping, a
# comment or history syntax in bash or zsh.
_ACTIVE = frozenset(";&|<>()$`{}*?[]~#!^")
# Inside double quotes the shell still expands these.
_ACTIVE_IN_DOUBLE_QUOTES = frozenset("$`!")


def problem(line: str) -> str | None:
    """What a shell would do beyond splitting `line` into literal words, or None."""
    if not isinstance(line, str):
        raise TypeError("command line must be a string")
    if not line.strip():
        return "an empty command"
    for ch in line:
        if ch in "\n\r":
            return "a line break (more than one command)"
        if (ord(ch) < 0x20 and ch != "\t") or ch == "\x7f":
            return "a control character"
    quote = None
    word_start = True
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if quote is None:
            if c in " \t":
                word_start = True
                i += 1
                continue
            if c == "\\":
                # Outside quotes a backslash makes the next character literal,
                # in the shell and in shlex alike.
                if i + 1 >= n:
                    return "a trailing backslash"
                i += 2
                word_start = False
                continue
            if c in "'\"":
                quote = c
            elif c in _ACTIVE:
                return f"an unquoted {c!r}"
            elif c == "=" and word_start:
                return "a word that starts with '=' (zsh expands it to a command path)"
            word_start = False
        elif quote == "'":
            if c == "'":
                quote = None
        else:
            # In double quotes shlex only unescapes `"` and `\`; for those two
            # the shell agrees. `\$` and `` \` `` differ, so `$` and backticks
            # are refused below whether escaped or not.
            if c == "\\" and i + 1 < n and line[i + 1] in '"\\':
                i += 2
                continue
            if c == '"':
                quote = None
            elif c in _ACTIVE_IN_DOUBLE_QUOTES:
                return f"{c!r} inside double quotes"
        i += 1
    if quote is not None:
        return "an unterminated quote"
    return None
