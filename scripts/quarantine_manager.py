
import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

BASE = Path(__file__).resolve().parent.parent
QUARANTINE = BASE / "quarantine"
MANIFEST = QUARANTINE / "manifest.jsonl"


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def quarantine_file(file_path):
    source = Path(file_path).resolve(strict=True)

    if not source.is_file() or source.is_symlink():
        print("[BLOCKED] Only regular files can be quarantined.")
        return False

    # Restrict this starter module to the project's test folder.
    allowed = (BASE / "test_samples").resolve()

    if not source.is_relative_to(allowed):
        print("[BLOCKED] Only files inside test_samples are allowed.")
        return False

    QUARANTINE.mkdir(parents=True, exist_ok=True)
    os.chmod(QUARANTINE, 0o700)

    if not os.access(source, os.R_OK):
        print("[ERROR] File is not readable.")
        return False

    print("\nFile:", source)
    print("SHA256:", sha256_file(source))

    approval = input("Do you approve quarantining this file? (yes/no): ")

    if approval.strip().lower() != "yes":
        print("[CANCELLED] Original file was not changed.")
        return False

    original_hash = sha256_file(source)
    original_stat = source.stat()

    destination = QUARANTINE / f"{uuid4().hex}_{source.name}"

    try:
        # Copy first; do not remove the original yet.
        shutil.copy2(source, destination)
        os.chmod(destination, 0o600)

        # Verify the quarantined copy.
        if sha256_file(destination) != original_hash:
            print("[ERROR] Hash verification failed.")
            print("Original file preserved. Quarantine copy:", destination)
            return False

        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "original_path": str(source),
            "quarantine_path": str(destination),
            "sha256": original_hash,
            "size_bytes": original_stat.st_size,
            "original_permissions": oct(stat.S_IMODE(original_stat.st_mode)),
            "status": "COPIED_AND_VERIFIED_ORIGINAL_PRESERVED"
        }

        # Record the operation before asking about original removal.
        with MANIFEST.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record) + "\n")
            file.flush()
            os.fsync(file.fileno())

        print("[SUCCESS] Verified quarantine copy:", destination)
        print("[PRESERVED] Original file is still present.")
        print("[INFO] No original file has been removed.")

        return True

    except (OSError, shutil.Error) as error:
        print("[ERROR] Quarantine operation failed:", error)
        print("[INFO] Check both original and quarantine locations.")
        return False
