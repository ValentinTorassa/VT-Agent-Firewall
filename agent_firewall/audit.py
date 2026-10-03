"""Append-only JSONL audit log. Fail-closed: if the store cannot be opened
or written, the gateway denies actions rather than acting unaudited.

The log lives OUTSIDE the sandbox (logs/audit.jsonl) and is not reachable
through any tool surface.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    import fcntl
except ImportError:  # no advisory locks (Windows): one writer per file
    fcntl = None


class AuditUnavailable(Exception):
    pass


class AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Preflight: the handle is held open for the gateway's lifetime so
            # a mid-run failure is unlikely; a failure here is fail-closed.
            self._fh = open(self.path, "a", encoding="utf-8")
        except OSError as e:
            raise AuditUnavailable(f"cannot open audit log {self.path}: {e}") from e

    def log(self, record: dict) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        # Several processes may append to one file (parallel agent-hook calls):
        # hold an exclusive lock for the whole record so lines never interleave.
        if fcntl is not None:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        try:
            self._fh.write(line)
            self._fh.flush()
            os.fsync(self._fh.fileno())
        finally:
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)

    def poison(self, record: dict) -> None:
        """Last-resort channel when the audit store itself fails mid-run."""
        print("AUDIT-STORE FAILURE: outcome unknown; action_id="
              f"{record.get('action_id', 'unknown')}", file=sys.stderr)

    def close(self) -> None:
        self._fh.close()
