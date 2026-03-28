# student_name: Swetha M
# roll_number: 727823TUCY049
# project_name: DockerSecurityScanner
# date: 2025-06-28

"""
Docker Security Scanner — tool_main.py
Scans running Docker containers and local images for common
security misconfigurations and policy violations.

Supported modes:
  --mode full        : scan both containers and images (default)
  --mode containers  : scan running containers only
  --mode images      : scan local images only

Supported severity filter (containers mode):
  --severity HIGH | MEDIUM | LOW | ALL (default: ALL)
"""

import argparse
import datetime
import json
import sys
import os

ROLL_NUMBER = "727823TUCY049"
STUDENT_NAME = "Swetha M"
PROJECT_NAME = "DockerSecurityScanner"

# ─────────────────────────── helpers ────────────────────────────

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def banner():
    print("=" * 60)
    print(f"  Docker Security Scanner")
    print(f"  Student : {STUDENT_NAME}  |  Roll : {ROLL_NUMBER}")
    print(f"  Time    : {ts()}")
    print("=" * 60)

def get_client():
    """Return a Docker client, or raise a clear error."""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return client
    except ImportError:
        print("[ERROR] 'docker' SDK not installed. Run: pip install docker")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Cannot reach Docker daemon: {exc}")
        print("[HINT ] Is Docker running? Try: sudo systemctl start docker")
        sys.exit(1)

# ─────────────────────────── checks ─────────────────────────────

def check_exposed_ports(container):
    """Flag ports bound to 0.0.0.0 (exposed on all network interfaces)."""
    issues = []
    ports = container.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
    for port, bindings in ports.items():
        if bindings:
            for b in bindings:
                if b.get("HostIp") == "0.0.0.0":
                    issues.append(
                        f"Port {port} exposed on ALL interfaces "
                        f"(0.0.0.0:{b.get('HostPort')})"
                    )
    return issues

def check_privileged(container):
    """Detect containers running in privileged mode."""
    if container.attrs.get("HostConfig", {}).get("Privileged", False):
        return ["Container is running in PRIVILEGED mode — full host access"]
    return []

def check_root_user(container):
    """Detect containers whose process runs as root (UID 0)."""
    user = container.attrs.get("Config", {}).get("User", "")
    if user in ("", "root", "0"):
        return ["Container process runs as ROOT (UID 0)"]
    return []

def check_resource_limits(container):
    """Warn when no memory or CPU limits are configured."""
    issues = []
    hc = container.attrs.get("HostConfig", {})
    if hc.get("Memory", 0) == 0:
        issues.append("No memory limit set (OOM risk)")
    if hc.get("CpuQuota", 0) == 0:
        issues.append("No CPU quota set (resource exhaustion risk)")
    return issues

def check_writable_rootfs(container):
    """Flag containers whose root filesystem is not read-only."""
    if not container.attrs.get("HostConfig", {}).get("ReadonlyRootfs", False):
        return ["Root filesystem is WRITABLE (consider --read-only)"]
    return []

def severity_label(issues):
    """Assign a severity label based on the issues found."""
    high_keywords = {"PRIVILEGED", "ROOT"}
    for issue in issues:
        if any(kw in issue for kw in high_keywords):
            return "HIGH"
    return "MEDIUM" if issues else "LOW"

def check_image_age(image):
    """Warn when an image was built more than 180 days ago."""
    created_str = image.attrs.get("Created", "")
    if created_str:
        created = datetime.datetime.fromisoformat(created_str[:19])
        age = (datetime.datetime.utcnow() - created).days
        if age > 180:
            return [f"Image is {age} days old (>180 days — may lack security patches)"]
    return []

def check_image_no_tag(image):
    """Flag images with no human-readable tag (dangling images)."""
    if not image.tags:
        return ["Image has no tag (dangling image — hard to audit)"]
    return []

# ─────────────────────────── scanners ───────────────────────────

def scan_containers(client, severity_filter="ALL"):
    print(f"\n[{ts()}] Scanning running containers ...")
    findings = []
    containers = client.containers.list()
    if not containers:
        print(f"[{ts()}] No running containers found.")
        return findings

    for c in containers:
        c.reload()
        issues = (
            check_exposed_ports(c)
            + check_privileged(c)
            + check_root_user(c)
            + check_resource_limits(c)
            + check_writable_rootfs(c)
        )
        sev = severity_label(issues)
        if severity_filter != "ALL" and sev != severity_filter:
            continue
        findings.append({
            "container_id":   c.short_id,
            "container_name": c.name,
            "image":          c.image.tags or ["<no-tag>"],
            "status":         c.status,
            "issues":         issues,
            "severity":       sev,
        })
        status_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
        print(f"  {status_icon} [{sev}] {c.name} ({c.short_id}) — {len(issues)} issue(s)")

    return findings


def scan_images(client):
    print(f"\n[{ts()}] Scanning local images ...")
    findings = []
    images = client.images.list()
    if not images:
        print(f"[{ts()}] No local images found.")
        return findings

    for img in images:
        issues = check_image_age(img) + check_image_no_tag(img)
        findings.append({
            "image_id": img.short_id,
            "tags":     img.tags or ["<no-tag>"],
            "issues":   issues,
            "severity": severity_label(issues),
        })
        sev = severity_label(issues)
        tag_str = ", ".join(img.tags) if img.tags else "<no-tag>"
        print(f"  [{sev}] {tag_str} — {len(issues)} issue(s)")

    return findings

# ─────────────────────────── main ────────────────────────────────

def run_scan(mode="full", severity_filter="ALL", test_case=1):
    banner()
    print(f"[{ts()}] Roll Number : {ROLL_NUMBER}")
    print(f"[{ts()}] Mode        : {mode}  |  Severity filter : {severity_filter}")
    print(f"[{ts()}] Test Case   : TC{test_case}")

    client = get_client()

    container_findings = []
    image_findings = []

    if mode in ("full", "containers"):
        container_findings = scan_containers(client, severity_filter)

    if mode in ("full", "images"):
        image_findings = scan_images(client)

    report = {
        "scan_metadata": {
            "student_name":    STUDENT_NAME,
            "roll_number":     ROLL_NUMBER,
            "project_name":    PROJECT_NAME,
            "scan_time":       ts(),
            "test_case":       test_case,
            "mode":            mode,
            "severity_filter": severity_filter,
        },
        "container_findings": container_findings,
        "image_findings":     image_findings,
        "summary": {
            "containers_scanned": len(container_findings),
            "images_scanned":     len(image_findings),
            "container_issues":   sum(len(f["issues"]) for f in container_findings),
            "image_issues":       sum(len(f["issues"]) for f in image_findings),
        },
    }

    out_file = (
        f"scan_results_tc{test_case}_"
        f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(out_file, "w") as fh:
        json.dump(report, fh, indent=2)

    print(f"\n[{ts()}] ─── SUMMARY ──────────────────────────────")
    print(f"  Containers scanned : {report['summary']['containers_scanned']}")
    print(f"  Container issues   : {report['summary']['container_issues']}")
    print(f"  Images scanned     : {report['summary']['images_scanned']}")
    print(f"  Image issues       : {report['summary']['image_issues']}")
    print(f"  Output file        : {out_file}")
    print(f"[{ts()}] Scan complete.")
    return out_file, report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Docker Security Scanner — 727823TUCY049")
    parser.add_argument(
        "--mode",
        choices=["full", "containers", "images"],
        default="full",
        help="Scan mode (default: full)",
    )
    parser.add_argument(
        "--severity",
        choices=["HIGH", "MEDIUM", "LOW", "ALL"],
        default="ALL",
        help="Show containers at or above this severity (default: ALL)",
    )
    parser.add_argument(
        "--tc",
        type=int,
        default=1,
        help="Test case number for output file naming (default: 1)",
    )
    args = parser.parse_args()
    run_scan(mode=args.mode, severity_filter=args.severity, test_case=args.tc)
