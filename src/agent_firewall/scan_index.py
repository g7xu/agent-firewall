"""Saved scan results, stored as fingerprints and labels.

A list of where someone's private files live is itself sensitive, so paths are only
ever stored hashed and file contents are never stored.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

SENSITIVE_LABELS = {"financial", "health", "identity", "canary"}
# A folder counts as sensitive only with several hits that make up a real share of its files,
# so one stray document doesn't taint everything beside it.
FOLDER_MIN_SENSITIVE = 3
FOLDER_MIN_SHARE = 0.3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path_hash TEXT PRIMARY KEY,
    dir_hash TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL,
    size INTEGER NOT NULL,
    labels TEXT NOT NULL,
    method TEXT NOT NULL,
    sensitive INTEGER NOT NULL,
    unreadable INTEGER NOT NULL,
    scanned_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS files_by_dir ON files (dir_hash);
"""


def _fingerprint(path: str) -> str:
    return hashlib.sha256(os.path.realpath(path).encode()).hexdigest()


class ScanIndex:
    """Safe to share across threads: every statement runs under one lock."""

    def __init__(self, path: str):
        location = Path(path).expanduser()
        location.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(location), check_same_thread=False)
        location.chmod(0o600)
        self._db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;" + _SCHEMA)
        self._db.commit()

    def get(self, path: str, stat: os.stat_result) -> tuple[set[str], str] | None:
        """Return saved labels and method, or None if the file changed since it was scanned."""
        with self._lock:
            row = self._db.execute(
                "SELECT mtime_ns, size, labels, method FROM files WHERE path_hash = ?",
                (_fingerprint(path),),
            ).fetchone()
        if row is None or row[0] != stat.st_mtime_ns or row[1] != stat.st_size:
            return None
        return set(json.loads(row[2])), row[3]

    def put(self, path: str, stat: os.stat_result, labels: set[str], method: str) -> None:
        real = os.path.realpath(path)
        row = (
            _fingerprint(real), _fingerprint(os.path.dirname(real)), stat.st_mtime_ns, stat.st_size,
            json.dumps(sorted(labels)), method, int(bool(labels & SENSITIVE_LABELS)),
            int("opaque" in labels), time.time(),
        )
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?,?,?,?)", row)
            self._db.commit()

    def folder_labels(self, directory: str) -> set[str]:
        """Return the data types a folder mostly holds; empty if it isn't a sensitive folder."""
        with self._lock:
            rows = self._db.execute(
                "SELECT labels, sensitive FROM files WHERE dir_hash = ?", (_fingerprint(directory),)
            ).fetchall()
        hits = [set(json.loads(labels)) for labels, sensitive in rows if sensitive]
        if len(hits) < FOLDER_MIN_SENSITIVE or len(hits) / len(rows) < FOLDER_MIN_SHARE:
            return set()
        return set().union(*hits) & (SENSITIVE_LABELS - {"canary"})

    def stats(self) -> dict[str, int]:
        with self._lock:
            total, sensitive, unreadable = self._db.execute(
                "SELECT COUNT(*), COALESCE(SUM(sensitive),0), COALESCE(SUM(unreadable),0) FROM files"
            ).fetchone()
        return {"checked": total, "sensitive": sensitive, "unreadable": unreadable}
