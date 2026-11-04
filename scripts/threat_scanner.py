
import subprocess
from pathlib import Path

from scripts.threat_report import save_report
from scripts.quarantine_manager import quarantine_file

BASE = Path(__file__).resolve().parent.parent
SCAN_FOLDER = BASE / "test_samples"


def scan_for_threats():
    print("\n===================================")
    print("     CYBERSHIELD THREAT SCANNER")
    print("===================================")

    # Restrict this first version to our test folder.
    if not SCAN_FOLDER.is_dir():
        print("[ERROR] Test folder does not exist:", SCAN_FOLDER)
        return

    command = [
        "clamscan",
        "--recursive",
        "--infected",
        "--no-summary",
        str(SCAN_FOLDER)
    ]

    print("\n[INFO] Starting ClamAV scan...")
    print("[TARGET]", SCAN_FOLDER)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False
        )

    except FileNotFoundError:
        print("[ERROR] ClamAV clamscan command not found.")
        return

    except subprocess.TimeoutExpired:
        print("[ERROR] Scan timed out.")
        return

    findings = []

    # ClamAV exit codes: 0 = clean, 1 = infected, 2 = error.
    if result.returncode == 2:
        print("[ERROR] ClamAV reported a scanning error.")
        print(result.stderr or result.stdout)
        summary = {
            "scan_status": "ERROR",
            "scanner_exit_code": result.returncode,
            "infected_count": 0
        }
        save_report(SCAN_FOLDER, findings, summary)
        return

    for line in result.stdout.splitlines():
        if line.endswith(" FOUND"):
            file_name, detection = line.rsplit(": ", 1)

            findings.append({
                "file": file_name,
                "detection": detection[:-6],
                "status": "DETECTED"
            })

    print("\n========== SCAN RESULTS ==========")

    if not findings:
        print("[SAFE] No threats detected.")
    else:
        for number, item in enumerate(findings, start=1):
            print(f"\n{number}. THREAT DETECTED")
            print("File:", item["file"])
            print("Detection:", item["detection"])

            approval = input(
                "\nCopy this file into quarantine? (yes/no): "
            )

            if approval.strip().lower() == "yes":
                success = quarantine_file(item["file"])

                if success:
                    item["status"] = (
                        "QUARANTINE_COPY_VERIFIED_ORIGINAL_PRESERVED"
                    )
                else:
                    item["status"] = "QUARANTINE_NOT_COMPLETED"
            else:
                item["status"] = "DETECTED_NOT_QUARANTINED"

    summary = {
        "scan_status": "COMPLETED",
        "scanner_exit_code": result.returncode,
        "infected_count": len(findings),
        "quarantine_copies_verified": sum(
            1 for item in findings
            if item["status"] ==
            "QUARANTINE_COPY_VERIFIED_ORIGINAL_PRESERVED"
        )
    }

    save_report(SCAN_FOLDER, findings, summary)

    print("\n========== FINAL SUMMARY ==========")
    print("Threats detected:", len(findings))
    print("Quarantine copies verified:",
          summary["quarantine_copies_verified"])
    print("Original files were not removed.")


if __name__ == "__main__":
    scan_for_threats()
