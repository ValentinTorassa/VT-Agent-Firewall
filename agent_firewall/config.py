"""Gateway configuration: sandbox, protected paths, allowlists, MCP registry.

Relative paths in the config file are resolved against ``base_dir``
(default: the parent of the directory containing the config file, i.e. the
repo root for policies/default.json).
"""

from __future__ import annotations

import json
from pathlib import Path


class Config:
    def __init__(self, path: str | Path, base_dir: str | Path | None = None):
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        base = Path(base_dir) if base_dir else path.resolve().parent.parent
        base = base.resolve()

        self.sandbox_root = self._abs(base, raw["sandbox_root"])
        self.protected = {self._abs(base, p) for p in raw["protected_paths"]}
        self.writable_dirs = [self._abs(base, d) for d in raw["writable_dirs"]]
        self.shell_allowlist = set(raw["shell_allowlist"])
        self.shell_forbidden_args = {
            k: set(v) for k, v in raw.get("shell_forbidden_args", {}).items()
        }
        self.network_mode = raw.get("network", {}).get("mode", "deny_all")
        self.mcp_registry = {
            srv: set(tools) for srv, tools in raw.get("mcp_registry", {}).items()
        }
        self.approval_timeout_sec = int(raw.get("approval_timeout_sec", 30))

    @staticmethod
    def _abs(base: Path, p: str) -> Path:
        p = Path(p)
        return p.resolve() if p.is_absolute() else (base / p).resolve()

    def in_sandbox(self, resolved: Path) -> bool:
        return resolved == self.sandbox_root or self.sandbox_root in resolved.parents

    def is_protected(self, resolved: Path) -> bool:
        return resolved in self.protected

    def in_writable(self, resolved: Path) -> bool:
        return any(d == resolved or d in resolved.parents for d in self.writable_dirs)
