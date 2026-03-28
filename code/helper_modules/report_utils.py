# student_name: Swetha M
# roll_number: 727823TUCY049
# project_name: DockerSecurityScanner
# date: 2025-06-28

"""
helper_modules/report_utils.py
Utility functions shared across pipeline scripts.
"""

import json
import os
import glob
import datetime

ROLL_NUMBER = "727823TUCY049"


def latest_result_file(pattern="scan_results_*.json"):
    """Return the most recently created scan result JSON file."""
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def load_result(filepath):
    """Load a scan result JSON and return the parsed dict."""
    with open(filepath, "r") as fh:
        return json.load(fh)


def severity_counts(findings):
    """Count findings by severity level."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def print_table(rows, headers):
    """Print a simple plain-text table."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    fmt = "| " + " | ".join(f"{{:<{w}}}" for w in col_widths) + " |"

    print(sep)
    print(fmt.format(*headers))
    print(sep)
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))
    print(sep)


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
