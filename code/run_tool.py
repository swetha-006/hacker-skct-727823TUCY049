# Swetha M — 727823TUCY049
# student_name: Swetha M
# roll_number: 727823TUCY049
# project_name: DockerSecurityScanner
# date: 2025-06-28

"""
run_tool.py — Stage 2 of the Docker Security Scanner pipeline.

Executes 3 distinct test cases to demonstrate different features:

  TC1 — Full scan  : scans both containers AND images, all severities.
  TC2 — HIGH-only  : containers only, filtered to HIGH severity findings.
  TC3 — Images only: local image age and tag audit, no container scan.

Each test case writes its own timestamped JSON result file.
"""

import subprocess
import sys
import datetime
import os

ROLL_NUMBER = "727823TUCY049"
STUDENT_NAME = "Swetha M"

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_test_case(tc_number, mode, severity="ALL"):
    print(f"\n{'─' * 60}")
    print(f"[{ts()}] Roll Number : {ROLL_NUMBER}")
    print(f"[{ts()}] TEST CASE {tc_number} — mode={mode}, severity={severity}")
    print(f"{'─' * 60}")

    tool_path = os.path.join(os.path.dirname(__file__), "tool_main.py")
    cmd = (
        f"{sys.executable} {tool_path} "
        f"--mode {mode} --severity {severity} --tc {tc_number}"
    )
    result = subprocess.run(cmd, shell=True, text=True)

    if result.returncode == 0:
        print(f"[{ts()}] TC{tc_number} PASSED ✓")
    else:
        print(f"[{ts()}] TC{tc_number} FAILED (exit {result.returncode})")

    return result.returncode

def main():
    print("=" * 60)
    print(f"  RUN TOOL — Docker Security Scanner")
    print(f"  Roll Number : {ROLL_NUMBER}")
    print(f"  Timestamp   : {ts()}")
    print("=" * 60)

    results = {}

    # Test Case 1: Full scan — containers + images, all severities
    results[1] = run_test_case(
        tc_number=1,
        mode="full",
        severity="ALL",
    )

    # Test Case 2: Containers only, HIGH severity filter
    results[2] = run_test_case(
        tc_number=2,
        mode="containers",
        severity="HIGH",
    )

    # Test Case 3: Images only — age and tag audit
    results[3] = run_test_case(
        tc_number=3,
        mode="images",
        severity="ALL",
    )

    # ── Final summary ─────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"[{ts()}] PIPELINE RUN SUMMARY")
    print(f"  Roll Number : {ROLL_NUMBER}")
    for tc, code in results.items():
        status = "PASS" if code == 0 else "FAIL"
        print(f"  TC{tc} : {status}")
    print(f"[{ts()}] All test cases executed.")
    print("=" * 60)

if __name__ == "__main__":
    main()
