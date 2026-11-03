"""Journal d'evenements (M2 -> M4/M5) : une ligne JSON par evenement, PAN TOKENISE uniquement."""
import json
from datetime import datetime, timezone
from pathlib import Path


class EventLog:
    def __init__(self, path: str = "data/processed/transactions.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, **event) -> None:
        event = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **event}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
