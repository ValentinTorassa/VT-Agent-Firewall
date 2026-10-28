"""Per-session state: the taint flag. Once any protected path is named or
reached (even by a blocked attempt), or a request carries a secret value, the
session is tainted and every later network, `api.call`, `shell_ask` and
`shell_exact` action is blocked with `taint-session`.

The gateway and the MCP proxy keep one SessionState for the life of the
process. The agent hook runs once per tool call, so it keeps a session's taint
in a TaintStore, a file next to its audit log, keyed by the host's session id.

This is path-level taint, not content-level dataflow analysis. Documented
limitation: reading an *allowed* file and pasting its content into an
*allowed* channel is not detected; a value from `secret_files` is (egress.py).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLogger, AuditUnavailable, fcntl


@dataclass
class SessionState:
    tainted: bool = False


class TaintUnavailable(Exception):
    """The taint store cannot be opened, read or written: the hook denies."""


class TaintStore:
    """Append-only JSONL of tainted sessions, one line per session, locked
    and fsynced like the audit log. A line that cannot be read counts as
    tainting every session: the store fails closed."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        try:
            self._log = AuditLogger(self.path)
        except AuditUnavailable as e:
            raise TaintUnavailable(f"cannot open the session taint store: "
                                   f"{e.__cause__ or e}") from e

    def tainted(self, session_id: str) -> bool:
        try:
            with open(self.path, encoding="utf-8") as fh:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        return True
                    if not isinstance(entry, dict) or entry.get("session_id") == session_id:
                        return True
        except (OSError, UnicodeDecodeError):
            return True
        return False

    def mark(self, session_id: str, **fields) -> None:
        try:
            self._log.log({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                           "session_id": session_id, **fields})
        except OSError as e:
            raise TaintUnavailable(f"cannot record the session's taint: {e}") from e

    def close(self) -> None:
        self._log.close()
