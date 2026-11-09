"""Background scan that finds sensitive files with no configuration.

Each folder is walked twice: quick text files first so most results exist within seconds,
then PDFs and images, which need OCR.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path

from .config import Settings
from .inspector import Inspection, inspect_file
from .scan_index import ScanIndex

MAX_FLAGGED_FILES = 50_000
_SKIP_DIRECTORIES = {"node_modules", "__pycache__", "Library", "venv"}
_SLOW_SUFFIXES = {".pdf", ".png", ".jpg", ".jpeg", ".heic", ".heif", ".tif", ".tiff", ".gif", ".bmp", ".webp"}


class Scanner:
    def __init__(self, settings: Settings, index: ScanIndex):
        self._settings = settings
        self._index = index
        self._queue: queue.Queue[str] = queue.Queue()
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._pending = 0
        self._running = False
        self._flagged: dict[str, tuple[list[str], str, float]] = {}

    def flagged_files(self) -> list[tuple[str, list[str], str, float]]:
        """Return flagged files by name. Kept in memory only: the saved index holds no paths."""
        with self._lock:
            return [(path, *details) for path, details in self._flagged.items()]

    def add_root(self, path: str) -> None:
        """Queue a folder once. Safe to call on every agent action."""
        root = os.path.realpath(os.path.expanduser(path))
        with self._lock:
            if root in self._seen:
                return
            self._seen.add(root)
        self._queue.put(root)

    def start(self) -> None:
        for root in self._settings.scan_roots:
            self.add_root(root)
        threading.Thread(target=self._work, daemon=True, name="afw-scanner").start()

    def status(self) -> dict[str, int | bool]:
        with self._lock:
            pending, running = self._pending, self._running
        return {**self._index.stats(), "pending": pending, "scanning": running or not self._queue.empty()}

    def _work(self) -> None:
        while True:
            root = self._queue.get()
            with self._lock:
                self._running = True
            try:
                self.scan(root)
            finally:
                with self._lock:
                    self._running = False

    def _remember(self, path: Path, result: Inspection | None) -> None:
        with self._lock:
            key = str(path)
            if result is None or not result.labels:
                self._flagged.pop(key, None)
            elif key in self._flagged or len(self._flagged) < MAX_FLAGGED_FILES:
                labels = sorted(result.labels)
                previous = self._flagged.get(key)
                found_at = previous[2] if previous and previous[0] == labels else time.time()
                self._flagged[key] = (labels, result.method, found_at)

    def scan(self, root: str) -> None:
        quick, slow = [], []
        for current, directories, files in os.walk(root):
            directories[:] = [d for d in directories if not d.startswith(".") and d not in _SKIP_DIRECTORIES]
            for name in files:
                path = Path(current, name)
                if not path.is_symlink():
                    (slow if path.suffix.lower() in _SLOW_SUFFIXES else quick).append(path)
        with self._lock:
            self._pending += len(quick) + len(slow)
        for path in quick + slow:
            try:
                self._remember(path, inspect_file(path, self._settings, self._index))
            finally:
                with self._lock:
                    self._pending -= 1
