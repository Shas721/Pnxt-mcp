import json
import logging
from datetime import datetime, timezone


def log_json(level: int, event: str, **fields) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    logging.getLogger("pointnxt").log(
        level, json.dumps(payload, separators=(",", ":"), default=str)
    )
