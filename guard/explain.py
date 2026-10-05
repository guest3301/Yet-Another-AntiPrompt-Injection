import datetime
import json
from pathlib import Path

from guard.models import ScanResult


class ExplainLog:
    def __init__(self, path="explain_log.jsonl"):
        self.path = Path(path)

    def record(self, event_type, input_preview, detail):
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event_type,
            "input_preview": str(input_preview)[:150],
            "detail": self._serialize(detail),
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def _serialize(self, obj):
        if isinstance(obj, ScanResult):
            return obj.__dict__
        if hasattr(obj, "__dataclass_fields__"):
            return {k: self._serialize(v) for k, v in obj.__dict__.items()}
        if isinstance(obj, dict):
            return {k: self._serialize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._serialize(i) for i in obj]
        return obj

    def read_recent(self, n=20):
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
