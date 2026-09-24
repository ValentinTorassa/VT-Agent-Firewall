"""Per-session state. Currently just the taint flag: once any protected
path is touched (even by a blocked attempt), the session is tainted and all
subsequent network-capable actions are blocked with `taint-session`.

This is path-level taint, not content-level dataflow analysis. Documented
v1 limitation: reading an *allowed* file and pasting its content into an
*allowed* channel is not detected.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SessionState:
    tainted: bool = False
