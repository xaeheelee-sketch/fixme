from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Any


class JsonlTracer:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields: Any) -> None:
        record = {"ts": time.time(), "event": event, **fields}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
