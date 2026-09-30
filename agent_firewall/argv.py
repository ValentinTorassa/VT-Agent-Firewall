"""Argument grammars for the allowlisted binaries.

The policy never guesses which argv tokens are paths. Each allowlisted binary
has a grammar (GNU coreutils / grep / findutils syntax) that says which options
exist, which take a value, which values are files, and which options make the
command walk a directory tree. Anything the grammar does not know is refused
(`sh-args`), so a new flag cannot smuggle a file past the path checks.

Binaries added to the allowlist without a grammar get a conservative fallback:
every operand and every `--opt=value` value is treated as a path, and `-r`,
`-R` or `--recursive` anywhere means a recursive walk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Value kinds for options that take an argument.
PATH = "path"            # the value is a file the command opens
VALUE = "value"          # a number, a glob, a format: not a path
PATTERN = "pattern"      # grep: the value is the pattern
PATTERN_FILE = "pattern-file"  # grep -f: the value is a file of patterns
DIRECTORIES = "directories"    # grep -d ACTION: `recurse` walks the tree


@dataclass(frozen=True)
class Grammar:
    flags: str = ""                                   # short options without a value
    short_values: dict = field(default_factory=dict)  # short option -> kind
    long_flags: frozenset = frozenset()
    long_values: dict = field(default_factory=dict)   # long option -> kind
    long_optional: frozenset = frozenset()            # --opt or --opt=WORD, never a path
    recursive_short: str = ""
    recursive_long: frozenset = frozenset()
    numeric_legacy: bool = False                      # `head -5`, `grep -3`
    pattern_first: bool = False                       # grep: first operand is the pattern
    default_walk_root: bool = False                   # recursive with no operand walks "."


@dataclass
class ParsedArgv:
    paths: list[str] = field(default_factory=list)       # every file the command may open
    walk_roots: list[str] = field(default_factory=list)  # trees it will descend
    max_depth: int | None = None                         # find -maxdepth
    errors: list[str] = field(default_factory=list)      # options outside the grammar


_COMMON_LONG = frozenset({"help", "version"})

GRAMMARS: dict[str, Grammar] = {
    "cat": Grammar(
        flags="AbeEnstTuv",
        long_flags=_COMMON_LONG | {"show-all", "number-nonblank", "show-ends", "number",
                                   "squeeze-blank", "show-tabs", "show-nonprinting"},
    ),
    "head": Grammar(
        flags="qvz", short_values={"c": VALUE, "n": VALUE},
        long_flags=_COMMON_LONG | {"quiet", "silent", "verbose", "zero-terminated"},
        long_values={"bytes": VALUE, "lines": VALUE}, numeric_legacy=True,
    ),
    # No -f/-F/--follow/--pid: a follow never ends and only burns the timeout.
    "tail": Grammar(
        flags="qvz", short_values={"c": VALUE, "n": VALUE, "s": VALUE},
        long_flags=_COMMON_LONG | {"quiet", "silent", "verbose", "zero-terminated"},
        long_values={"bytes": VALUE, "lines": VALUE, "sleep-interval": VALUE,
                     "max-unchanged-stats": VALUE},
        numeric_legacy=True,
    ),
    # No --files0-from: it reads the list of files to count from another file.
    "wc": Grammar(
        flags="cmlLw",
        long_flags=_COMMON_LONG | {"bytes", "chars", "lines", "max-line-length", "words"},
        long_values={"total": VALUE},
    ),
    # In ls, -r means reverse; only -R/--recursive walks the tree.
    "ls": Grammar(
        flags="aAbBcCdfFgGhHiklLmnNopqQrRsStuUvxXZ1",
        short_values={"I": VALUE, "w": VALUE, "T": VALUE},
        long_flags=_COMMON_LONG | {
            "all", "almost-all", "author", "escape", "human-readable", "si",
            "dereference", "dereference-command-line",
            "dereference-command-line-symlink-to-dir", "directory", "dired",
            "file-type", "full-time", "group-directories-first", "no-group", "inode",
            "kibibytes", "literal", "numeric-uid-gid", "hide-control-chars",
            "show-control-chars", "quote-name", "recursive", "reverse", "size", "zero",
            "context"},
        long_values={"hide": VALUE, "ignore": VALUE, "block-size": VALUE,
                     "format": VALUE, "sort": VALUE, "time": VALUE, "time-style": VALUE,
                     "indicator-style": VALUE, "quoting-style": VALUE, "tabsize": VALUE,
                     "width": VALUE},
        long_optional=frozenset({"color", "colour", "classify", "hyperlink"}),
        recursive_short="R", recursive_long=frozenset({"recursive"}),
        default_walk_root=True,
    ),
    # grep -r with no file walks the current directory (GNU grep >= 2.11).
    "grep": Grammar(
        flags="iyvwxclLnhHoqsrREFGPzZaIUTbV",
        short_values={"e": PATTERN, "f": PATTERN_FILE, "m": VALUE, "A": VALUE,
                      "B": VALUE, "C": VALUE, "d": DIRECTORIES, "D": VALUE},
        long_flags=_COMMON_LONG | {
            "extended-regexp", "fixed-strings", "basic-regexp", "perl-regexp",
            "ignore-case", "no-ignore-case", "word-regexp", "line-regexp", "null-data",
            "no-messages", "invert-match", "byte-offset", "line-number",
            "line-buffered", "with-filename", "no-filename", "only-matching", "quiet",
            "silent", "text", "recursive", "dereference-recursive", "initial-tab",
            "null", "count", "files-with-matches", "files-without-match",
            "no-group-separator"},
        long_values={"regexp": PATTERN, "file": PATTERN_FILE, "max-count": VALUE,
                     "after-context": VALUE, "before-context": VALUE, "context": VALUE,
                     "label": VALUE, "binary-files": VALUE, "devices": VALUE,
                     "directories": DIRECTORIES, "include": VALUE, "exclude": VALUE,
                     "exclude-from": PATH, "exclude-dir": VALUE,
                     "group-separator": VALUE},
        long_optional=frozenset({"color", "colour"}),
        recursive_short="rR",
        recursive_long=frozenset({"recursive", "dereference-recursive"}),
        numeric_legacy=True, pattern_first=True, default_walk_root=True,
    ),
}

# find: an allowlist of predicates. Actions that write (-fprint, -fls, ...),
# execute (-exec, -ok, ...) or delete are simply not in it.
_FIND_NO_ARG = frozenset({
    "-empty", "-readable", "-writable", "-executable", "-true", "-false", "-nouser",
    "-nogroup", "-depth", "-xdev", "-mount", "-noleaf", "-daystart", "-follow",
    "-ignore_readdir_race", "-noignore_readdir_race", "-print", "-print0", "-ls",
    "-prune", "-quit", "-not", "-a", "-and", "-o", "-or", "!", "(", ")", ",",
})
_FIND_VALUE_ARG = frozenset({
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex",
    "-iregex", "-lname", "-ilname", "-type", "-xtype", "-size", "-mtime", "-mmin",
    "-atime", "-amin", "-ctime", "-cmin", "-used", "-perm", "-user", "-group", "-uid",
    "-gid", "-links", "-inum", "-fstype", "-regextype", "-mindepth", "-printf",
})
_FIND_PATH_ARG = frozenset({"-newer", "-anewer", "-cnewer", "-samefile"})
_FIND_NEWERXY = re.compile(r"^-newer([aBcm])([aBcmt])$")
_FIND_PRE_OPTIONS = frozenset({"-H", "-L", "-P"})


def parse(binary: str, args: list[str]) -> ParsedArgv:
    if binary == "find":
        return _parse_find(args)
    grammar = GRAMMARS.get(binary)
    if grammar is None:
        return _parse_fallback(args)
    return _parse_gnu(grammar, args)


def _parse_gnu(g: Grammar, args: list[str]) -> ParsedArgv:
    out = ParsedArgv()
    operands: list[str] = []
    recursive = False
    pattern_given = False
    i, end_of_options = 0, False

    def take_value(kind: str, value: str) -> None:
        nonlocal recursive, pattern_given
        if kind == PATH:
            out.paths.append(value)
        elif kind == PATTERN:
            pattern_given = True
        elif kind == PATTERN_FILE:
            pattern_given = True
            out.paths.append(value)
        elif kind == DIRECTORIES and value == "recurse":
            recursive = True

    while i < len(args):
        arg = args[i]
        i += 1
        if end_of_options or arg == "-" or not arg.startswith("-"):
            operands.append(arg)          # GNU permutes: options may follow operands
            continue
        if arg == "--":
            end_of_options = True
            continue
        if arg.startswith("--"):
            name, eq, value = arg[2:].partition("=")
            if name in g.long_flags and not eq:
                recursive |= name in g.recursive_long
            elif name in g.long_optional:
                pass
            elif name in g.long_values:
                if not eq:
                    if i >= len(args):
                        out.errors.append(f"--{name} needs a value")
                        continue
                    value = args[i]
                    i += 1
                take_value(g.long_values[name], value)
            else:
                out.errors.append(f"--{name}")
            continue
        if g.numeric_legacy and arg[1:].isdigit():
            continue
        j = 1
        while j < len(arg):
            c = arg[j]
            j += 1
            if c in g.flags:
                recursive |= c in g.recursive_short
                continue
            if c in g.short_values:
                value = arg[j:]           # attached value: -f.env, -A3
                if not value:
                    if i >= len(args):
                        out.errors.append(f"-{c} needs a value")
                        break
                    value = args[i]
                    i += 1
                take_value(g.short_values[c], value)
                break
            out.errors.append(f"-{c}")
            break

    if g.pattern_first and not pattern_given and operands:
        operands = operands[1:]           # the first operand is the pattern
    files = [o for o in operands if o != "-"]
    out.paths.extend(files)
    if recursive:
        out.walk_roots = files or (["."] if g.default_walk_root else [])
    return out


def _parse_find(args: list[str]) -> ParsedArgv:
    out = ParsedArgv()
    i = 0
    while i < len(args) and args[i] in _FIND_PRE_OPTIONS:
        i += 1
    starts: list[str] = []
    while i < len(args) and not (args[i].startswith("-") or args[i] in ("(", ")", "!", ",")):
        starts.append(args[i])
        i += 1
    while i < len(args):
        token = args[i]
        i += 1
        if token in _FIND_NO_ARG:
            continue
        if token == "-maxdepth" or token in _FIND_VALUE_ARG or token in _FIND_PATH_ARG \
                or _FIND_NEWERXY.match(token):
            if i >= len(args):
                out.errors.append(f"{token} needs a value")
                break
            value = args[i]
            i += 1
            if token == "-maxdepth":
                try:
                    out.max_depth = int(value)
                except ValueError:
                    out.errors.append(f"-maxdepth {value!r} is not a number")
            elif token in _FIND_PATH_ARG:
                out.paths.append(value)
            else:
                m = _FIND_NEWERXY.match(token)
                if m and m.group(2) != "t":   # -newerXt takes a date, not a file
                    out.paths.append(value)
            continue
        out.errors.append(token)
        break
    starts = starts or ["."]
    out.paths.extend(starts)
    out.walk_roots = starts
    return out


def _parse_fallback(args: list[str]) -> ParsedArgv:
    out = ParsedArgv()
    operands: list[str] = []
    recursive = False
    end_of_options = False
    for arg in args:
        if end_of_options or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            end_of_options = True
        elif arg.startswith("--"):
            name, eq, value = arg[2:].partition("=")
            recursive |= name == "recursive"
            if eq:
                out.paths.append(value)
        else:
            recursive |= "r" in arg[1:] or "R" in arg[1:]
    out.paths.extend(o for o in operands if o != "-")
    if recursive:
        out.walk_roots = [o for o in operands if o != "-"] or ["."]
    return out
