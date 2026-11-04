import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
ALERT_DIR = BASE / "alerts"
ALERT_FILE = ALERT_DIR / "security_events.jsonl"

ALERT_DIR.mkdir(parents=True, exist_ok=True)


def send_alert(event, details):

    record = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event": event,
        "details": details
    }

    with ALERT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")
        file.flush()

    print("\n" + "=" * 45)
    print("[SECURITY ALERT]", event)
    print("Details:", details)
    print("=" * 45)
