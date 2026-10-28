"""Gateway configuration: sandbox, protected paths, allowlists, MCP registry.

Relative paths in the config file are resolved against ``base_dir``
(default: the parent of the directory containing the config file, i.e. the
repo root for policies/default.json).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from . import egress, network


DEFAULT_MCP_PATH_ARGUMENTS = [
    "path", "paths", "source", "destination", "file", "files", "filename",
    "filepath", "file_path", "dir", "directory", "src", "dest", "target", "root",
]


# A program name on shell_ask, or the first word of a shell_exact entry: one
# word, no assignment (`VAR=value cmd` runs cmd), no whitespace or controls.
_PROGRAM = re.compile(r"^[^\s=\x00-\x1f\x7f]+$")


@dataclass(frozen=True)
class ExactCommand:
    """One `shell_exact` entry: an argv allowed exactly as written.

    A bare program name matches only that spelling (`python3`, never
    `/usr/bin/python3` or `./python3`): which file it is, PATH decides. A
    program written with a slash resolves against the policy's base directory,
    and matches a request whose program resolves to the same file from the
    request's cwd, so `./run.sh` cannot be pointed at another script by
    changing directory.
    """
    argv: tuple[str, ...]
    program_path: Path | None

    def matches(self, argv: list[str], cwd: Path) -> bool:
        if len(argv) != len(self.argv) or tuple(argv[1:]) != self.argv[1:]:
            return False
        if self.program_path is None:
            return argv[0] == self.argv[0]
        if "/" not in argv[0] or "\0" in argv[0]:
            return False
        return Path(os.path.realpath(cwd / argv[0])) == self.program_path


class Config:
    def __init__(self, path: str | Path, base_dir: str | Path | None = None):
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        base = Path(base_dir) if base_dir else path.resolve().parent.parent
        self._load(raw, base.resolve())

    @classmethod
    def from_raw(cls, raw: dict, base_dir: str | Path) -> "Config":
        """A config from an already parsed policy (a proposal being checked)."""
        cfg = cls.__new__(cls)
        cfg._load(raw, Path(base_dir).resolve())
        return cfg

    def _load(self, raw: dict, base: Path) -> None:
        # Relative policy paths resolve here; a proposal writes new ones the same way.
        self.base_dir = base
        self.sandbox_root = self._abs(base, raw["sandbox_root"])
        self.protected = {self._abs(base, p) for p in raw["protected_paths"]}
        # Names protected wherever they appear under the sandbox (`.env.*`,
        # `*.pem`): a list of paths only covers the copies someone listed.
        self.protected_names = self._names(raw.get("protected_names", []))
        # Files whose values never leave in a request (egress.py). Each one is
        # a protected path too: the agent may not read it either.
        self.secret_files = [self._abs(base, p) for p in
                             self._strings(raw.get("secret_files", []), "secret_files")]
        self.protected.update(self.secret_files)
        self.secrets = egress.load(self.secret_files)
        self.writable_dirs = [self._abs(base, d) for d in raw["writable_dirs"]]
        self.shell_allowlist = set(raw["shell_allowlist"])
        self.shell_forbidden_args = {
            k: set(v) for k, v in raw.get("shell_forbidden_args", {}).items()
        }
        # Binaries the firewall cannot bound but a human may approve call by
        # call (`sh-ask`), and exact argv lists allowed as written (`sh-exact`).
        self.shell_ask = set(self._programs(raw.get("shell_ask", []), "shell_ask"))
        both = sorted(self.shell_allowlist & self.shell_ask)
        if both:
            raise ValueError(f"on both shell_allowlist and shell_ask: {both}")
        self.shell_exact = [self.exact_entry(base, entry, "shell_exact")
                            for entry in self._list(raw.get("shell_exact", []),
                                                    "shell_exact")]
        net = raw.get("network", {})
        self.network_mode = net.get("mode", "deny_all")
        # Only "allowlist" lets anything through. Any other mode denies all
        # network, as before the allowlist existed.
        allow = net.get("allow")
        if self.network_mode == "allowlist":
            self.network_allow = [network.parse_entry(e)
                                  for e in self._list(allow or [], "network.allow")]
        elif allow not in (None, []):
            raise ValueError('network.allow needs "mode": "allowlist"')
        else:
            self.network_allow = []
        self.mcp_registry = {
            srv: set(tools) for srv, tools in raw.get("mcp_registry", {}).items()
        }
        # MCP tool arguments that always carry filesystem paths. Any other string
        # argument that looks like a path is checked too (see policy._mcp_call);
        # this list only removes the guesswork for the common names.
        self.mcp_path_arguments = set(raw.get(
            "mcp_path_arguments", DEFAULT_MCP_PATH_ARGUMENTS))
        # Relative MCP path arguments resolve against the server's own root when
        # the policy names it, else against the sandbox root.
        self.mcp_roots = {srv: self._abs(base, root)
                          for srv, root in raw.get("mcp_roots", {}).items()}
        # MCP resources (resources/read and friends) are denied unless a server
        # is listed here: their URIs can name any file the server can reach.
        self.mcp_resources = set(raw.get("mcp_resources", []))
        # Extra JSON-RPC methods the MCP proxy relays untouched (the standard
        # ones are built in; anything else is refused).
        self.mcp_relay_methods = set(raw.get("mcp_relay_methods", []))
        # Audit records keep a hash and length of written content and a short
        # preview of network bodies unless verbose audit is turned on.
        self.audit_verbose = bool(raw.get("audit", {}).get("verbose", False))
        self.approval_timeout_sec = int(raw.get("approval_timeout_sec", 30))
        # audience -> operation -> {"scope": ..., "decision": allow|require_approval|block}
        self.apis = {
            aud: {op: dict(rule) for op, rule in ops.items()}
            for aud, ops in raw.get("apis", {}).items()
        }

    @staticmethod
    def _list(value, key: str) -> list:
        if not isinstance(value, list):
            raise ValueError(f"{key} must be a list")
        return value

    @classmethod
    def _strings(cls, value, key: str) -> list[str]:
        items = cls._list(value, key)
        for item in items:
            if not isinstance(item, str) or not item or "\0" in item:
                raise ValueError(f"{key}: {item!r} is not a path")
        return items

    @classmethod
    def _names(cls, value) -> tuple[str, ...]:
        names = cls._list(value, "protected_names")
        for name in names:
            if not isinstance(name, str) or not name or "/" in name or "\0" in name \
                    or name in (".", ".."):
                raise ValueError(f"protected_names: {name!r} is not a file or directory "
                                 f"name pattern (one name, no slash, e.g. \".env.*\")")
        return tuple(names)

    @classmethod
    def _programs(cls, value, key: str) -> list[str]:
        names = cls._list(value, key)
        for name in names:
            if not isinstance(name, str) or not _PROGRAM.match(name) or "/" in name:
                raise ValueError(f"{key}: {name!r} is not a program name (one word, "
                                 f"no path, no VAR=value)")
        return names

    @classmethod
    def exact_entry(cls, base: Path, entry, key: str = "shell_exact") -> ExactCommand:
        if not (isinstance(entry, list) and entry
                and all(isinstance(w, str) and "\0" not in w for w in entry)):
            raise ValueError(f"{key}: {entry!r} is not an argv list such as "
                             f'["python3", "-m", "pytest"]')
        program = entry[0]
        if not _PROGRAM.match(program):
            raise ValueError(f"{key}: {program!r} is not a program (one word, no "
                             f"VAR=value; write the command as a list of words)")
        return ExactCommand(tuple(entry),
                            cls._abs(base, program) if "/" in program else None)

    def exact_command(self, argv: list[str], cwd: Path) -> ExactCommand | None:
        """The shell_exact entry this argv matches, run from `cwd`, if any."""
        return next((e for e in self.shell_exact if e.matches(argv, cwd)), None)

    @staticmethod
    def _abs(base: Path, p: str) -> Path:
        p = Path(p)
        return p.resolve() if p.is_absolute() else (base / p).resolve()

    def in_sandbox(self, resolved: Path) -> bool:
        return resolved == self.sandbox_root or self.sandbox_root in resolved.parents

    def is_protected(self, resolved: Path) -> bool:
        """A protected entry covers itself and everything below it, so a
        protected directory cannot be read file by file. A name on
        `protected_names` covers every file or directory with that name, and
        everything below it."""
        if any(p == resolved or p in resolved.parents for p in self.protected):
            return True
        return bool(self.protected_names) and self.name_protected(resolved) is not None

    def name_protected(self, resolved: Path) -> str | None:
        """The `protected_names` pattern a name in this path matches, if any.
        Names are matched below the sandbox root (the directories above it are
        not the agent's to name); a path outside it is matched whole."""
        try:
            parts = resolved.relative_to(self.sandbox_root).parts
        except ValueError:
            parts = resolved.parts
        for part in parts:
            for pattern in self.protected_names:
                if fnmatchcase(part, pattern):
                    return pattern
        return None

    def protected_under(self, root: Path, max_depth: int | None = None) -> Path | None:
        """First protected path inside the tree rooted at `root` (depth-limited
        like `find -maxdepth`: the root is depth 0), or None."""
        for p in sorted(self.protected):
            if p == root or root in p.parents:
                if max_depth is None or len(p.relative_to(root).parts) <= max_depth:
                    return p
        return None

    def in_writable(self, resolved: Path) -> bool:
        return any(d == resolved or d in resolved.parents for d in self.writable_dirs)

