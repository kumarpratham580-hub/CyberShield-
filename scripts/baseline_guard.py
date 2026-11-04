import shutil
import hashlib
import hmac
import json
import os
import secrets

from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

PROTECTED = BASE / "protected_files"
REPORTS = BASE / "reports"

CONFIG = Path.home() / ".config" / "cybershield"
KEY_FILE = CONFIG / "baseline.key"

BASELINE = REPORTS / "secure_baseline.json"
SIGNATURE = REPORTS / "baseline.signature"


def prepare():
    CONFIG.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    if not KEY_FILE.exists():
        fd = os.open(
            KEY_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )

        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))


def get_key():
    prepare()
    return KEY_FILE.read_bytes()


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def create_signed_baseline():

    prepare()

    records = {}

    for file in sorted(PROTECTED.rglob("*")):

        if not file.is_file() or file.is_symlink():
            continue

        # Step 1: Get relative file path
        relative = file.relative_to(PROTECTED).as_posix()

        # Step 2: Create backup location
        backup = BASE / "backups" / relative

        backup.parent.mkdir(parents=True, exist_ok=True)

        # Step 3: Create backup only if it doesn't exist
        if not backup.exists():
            shutil.copy2(file, backup)

        # Step 4: Calculate hash and permissions
        records[relative] = {
            "sha256": sha256_file(file),
            "permissions": oct(file.stat().st_mode & 0o777)
        }

    # Step 5: Convert baseline to JSON
    data = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    # Step 6: Generate HMAC signature
    signature = hmac.new(
        get_key(),
        data,
        hashlib.sha256
    ).hexdigest()

    # Step 7: Save baseline and signature
    BASELINE.write_bytes(data)
    SIGNATURE.write_text(signature)

    os.chmod(BASELINE, 0o600)
    os.chmod(SIGNATURE, 0o600)

    print("[SUCCESS] Signed baseline created.")

def verify_baseline():

    prepare()

    if not BASELINE.is_file() or not SIGNATURE.is_file():
        print("[CRITICAL] Baseline or signature missing!")
        return False

    data = BASELINE.read_bytes()
    stored_signature = SIGNATURE.read_text().strip()

    expected_signature = hmac.new(
        get_key(),
        data,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(
        stored_signature,
        expected_signature
    ):
        print("[CRITICAL] BASELINE TAMPERING DETECTED!")
        return False

    print("[SAFE] Baseline signature verified.")
    return True


if __name__ == "__main__":

    print("1. Create signed baseline")
    print("2. Verify baseline")

    choice = input("Choose: ")

    if choice == "1":
        create_signed_baseline()

    elif choice == "2":
        verify_baseline()
