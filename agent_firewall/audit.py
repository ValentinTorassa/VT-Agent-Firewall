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
        self._fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def poison(self, record: dict) -> None:
        """Last-resort channel when the audit store itself fails mid-run."""
        print(f"AUDIT-STORE FAILURE, unaudited record: {record}", file=sys.stderr)

    def close(self) -> None:
        self._fh.close()
