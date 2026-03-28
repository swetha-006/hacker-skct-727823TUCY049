# Swetha M — 727823TUCY049
# student_name: Swetha M
# roll_number: 727823TUCY049
# project_name: DockerSecurityScanner
# date: 2025-06-28

"""
analyze_results.py — Stage 3 of the Docker Security Scanner pipeline.

Reads all scan_results_*.json files produced by run_tool.py,
consolidates findings, prints a severity breakdown table, and
writes a final consolidated_report.json.
"""

import glob
import json
import os
import sys
import datetime

ROLL_NUMBER = "727823TUCY049"
STUDENT_NAME = "Swetha M"

# Add helper_modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "helper_modules"))
from report_utils import severity_counts, print_table, latest_result_file

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_all_results():
    files = sorted(glob.glob("scan_results_*.json"), key=os.path.getmtime)
    if not files:
        print(f"[{ts()}] No scan result files found. Run run_tool.py first.")
        sys.exit(1)
    results = []
    for f in files:
        with open(f) as fh:
            results.append((f, json.load(fh)))
    return results

def analyse(results):
    all_container_findings = []
    all_image_findings = []

    for fname, data in results:
        all_container_findings.extend(data.get("container_findings", []))
        all_image_findings.extend(data.get("image_findings", []))

    return all_container_findings, all_image_findings

def main():
    print("=" * 60)
    print(f"  ANALYZE RESULTS — Docker Security Scanner")
    print(f"  Roll Number : {ROLL_NUMBER}")
    print(f"  Timestamp   : {ts()}")
    print("=" * 60)

    results = load_all_results()
    print(f"\n[{ts()}] Loaded {len(results)} result file(s).")

    container_findings, image_findings = analyse(results)

    # ── Container severity table ──────────────────────────────────
    print(f"\n[{ts()}] ─── Container Security Findings ─────────────────")
    if container_findings:
        rows = []
        for f in container_findings:
            issue_str = "; ".join(f["issues"]) if f["issues"] else "None"
            rows.append([
                f["container_name"],
                f["severity"],
                issue_str[:60] + ("..." if len(issue_str) > 60 else ""),
            ])
        print_table(rows, ["Container", "Severity", "Issues (truncated)"])
    else:
        print("  No container findings.")

    # ── Image findings table ──────────────────────────────────────
    print(f"\n[{ts()}] ─── Image Findings ──────────────────────────────")
    if image_findings:
        rows = []
        for f in image_findings:
            tag_str = ", ".join(f["tags"]) if f["tags"] else "<no-tag>"
            issue_str = "; ".join(f["issues"]) if f["issues"] else "None"
            rows.append([
                tag_str[:30],
                f["severity"],
                issue_str[:50] + ("..." if len(issue_str) > 50 else ""),
            ])
        print_table(rows, ["Image", "Severity", "Issues (truncated)"])
    else:
        print("  No image findings.")

    # ── Overall severity breakdown ────────────────────────────────
    print(f"\n[{ts()}] ─── Severity Breakdown ──────────────────────────")
    c_counts = severity_counts(container_findings)
    i_counts = severity_counts(image_findings)
    print_table(
        [
            ["Containers", c_counts["HIGH"], c_counts["MEDIUM"], c_counts["LOW"]],
            ["Images",     i_counts["HIGH"], i_counts["MEDIUM"], i_counts["LOW"]],
        ],
        ["Scope", "HIGH", "MEDIUM", "LOW"],
    )

    # ── Remediation suggestions ───────────────────────────────────
    print(f"\n[{ts()}] ─── Remediation Suggestions ─────────────────────")
    suggestions = {
        "PRIVILEGED":        "Remove --privileged flag; use specific capabilities with --cap-add.",
        "ROOT":              "Add USER directive in Dockerfile to run as non-root.",
        "No memory limit":   "Set --memory in docker run or deploy limits in compose.",
        "No CPU quota":      "Set --cpus or cpu_quota in compose to prevent resource starvation.",
        "exposed on ALL":    "Bind ports to 127.0.0.1 unless external access is required.",
        "WRITABLE":          "Use --read-only flag and mount /tmp as tmpfs if writes needed.",
        "180 days":          "Rebuild images regularly to apply upstream security patches.",
        "no tag":            "Tag all images; remove dangling images with docker image prune.",
    }
    all_issues = []
    for f in container_findings + image_findings:
        all_issues.extend(f.get("issues", []))

    shown = set()
    for issue in all_issues:
        for keyword, advice in suggestions.items():
            if keyword.lower() in issue.lower() and keyword not in shown:
                print(f"  • {advice}")
                shown.add(keyword)

    if not shown:
        print("  No actionable issues found — environment looks clean.")

    # ── Write consolidated report ─────────────────────────────────
    consolidated = {
        "roll_number":        ROLL_NUMBER,
        "student_name":       STUDENT_NAME,
        "analysis_time":      ts(),
        "files_analysed":     [f for f, _ in results],
        "container_findings": container_findings,
        "image_findings":     image_findings,
        "severity_breakdown": {
            "containers": c_counts,
            "images":     i_counts,
        },
    }
    out = "consolidated_report.json"
    with open(out, "w") as fh:
        json.dump(consolidated, fh, indent=2)

    print(f"\n[{ts()}] Consolidated report saved → {out}")
    print(f"[{ts()}] Roll Number : {ROLL_NUMBER} | Analysis complete.")

if __name__ == "__main__":
    main()
