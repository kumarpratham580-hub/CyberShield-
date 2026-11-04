
import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE / "reports"


def save_report(target, findings, summary):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    filename = timestamp.strftime("threat_report_%Y%m%d_%H%M%S_%f.json")
    report_file = REPORT_DIR / filename

    report = {
        "tool": "CyberShield",
        "scan_time_utc": timestamp.isoformat(),
        "target": str(target),
        "summary": summary,
        "findings": findings
    }

    # Exclusive creation prevents accidentally overwriting an old report.
    with report_file.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n[REPORT SAVED]", report_file)
    return report_file
