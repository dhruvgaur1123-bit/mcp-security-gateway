"""Append-only JSONL audit log with an in-memory tail and counters."""
from __future__ import annotations

import json
import threading
import time
from collections import Counter, deque
from pathlib import Path


class Audit:
    def __init__(self, path: str | Path | None = None, keep: int = 1000):
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self.recent: deque = deque(maxlen=keep)
        self.counts: Counter = Counter()

    def log(self, event: str, decision: str, **fields) -> dict:
        rec = {"ts": round(time.time(), 3), "event": event, "decision": decision, **fields}
        with self._lock:
            self.recent.append(rec)
            self.counts[decision] += 1
            self.counts[f"event:{event}"] += 1
            if self._path:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def tail(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self.recent)[-limit:]

    def stats(self) -> dict:
        with self._lock:
            return dict(self.counts)
