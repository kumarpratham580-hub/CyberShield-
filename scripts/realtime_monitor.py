import json
import shutil
import time

from pathlib import Path
from datetime import datetime, timezone

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from scripts.baseline_guard import (
    verify_baseline,
    sha256_file,
    BASELINE,
    SIGNATURE,
    PROTECTED,
    REPORTS
)

from scripts.alert_system import send_alert


BASE = Path(__file__).resolve().parent.parent

EVIDENCE = BASE / "evidence"


def load_records():
    return json.loads(BASELINE.read_text())


def preserve_evidence(source, event_type):

    if not source.is_file() or source.is_symlink():
        return

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S_%f")

    destination = (
        EVIDENCE / timestamp / source.name
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    shutil.copy2(source, destination)

    send_alert(
        "EVIDENCE_PRESERVED",
        f"{event_type}: {destination}"
    )


class SecurityHandler(FileSystemEventHandler):

    def process(self, path, event_type):

        path = Path(path)

        if path.is_symlink() or not path.exists():
            return

        if not path.is_file():
            return

        if not verify_baseline():
            send_alert(
                "BASELINE_TAMPERING",
                "Monitoring stopped because trusted baseline failed."
            )
            raise SystemExit("Baseline integrity failure")

        relative = path.relative_to(
            PROTECTED
        ).as_posix()

        records = load_records()
        original = records.get(relative)

        current_hash = sha256_file(path)

        if original is None:

            send_alert(
                "NEW_FILE",
                relative
            )

            preserve_evidence(path, "NEW FILE")
            return

        current_permissions = oct(
            path.stat().st_mode & 0o777
        )

        if current_hash != original["sha256"]:

            send_alert(
                "FILE_MODIFIED",
                relative
            )

            preserve_evidence(path, "MODIFIED FILE")

        if current_permissions != original["permissions"]:

            send_alert(
                "PERMISSION_CHANGED",
                relative
            )

    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path, "MODIFIED")

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path, "CREATED")

    def on_deleted(self, event):
        if not event.is_directory:
            send_alert(
                "FILE_DELETED",
                event.src_path
            )

    def on_moved(self, event):
        if not event.is_directory:
            send_alert(
                "FILE_MOVED",
                f"{event.src_path} -> {event.dest_path}"
            )

            if Path(event.dest_path).is_file():
                self.process(event.dest_path, "MOVED")


def start_monitor():

    if not verify_baseline():
        send_alert(
            "MONITOR_START_BLOCKED",
            "Trusted baseline verification failed."
        )
        return

    observer = Observer()

    handler = SecurityHandler()

    observer.schedule(
        handler,
        str(PROTECTED),
        recursive=True
    )

    observer.start()

    send_alert(
        "MONITOR_STARTED",
        "CyberShield real-time protection is running."
    )

    print("\nCyberShield real-time monitoring active.")
    print("Press CTRL+C to stop.")

    try:

        while True:

            time.sleep(5)

            if not verify_baseline():
                send_alert(
                    "BASELINE_TAMPERING",
                    "Monitoring stopped due to baseline tampering."
                )

                observer.stop()
                break

    except KeyboardInterrupt:

        print("\nStopping monitoring...")

    finally:

        observer.stop()
        observer.join()

        print("CyberShield monitoring stopped.")


if __name__ == "__main__":
    start_monitor()
