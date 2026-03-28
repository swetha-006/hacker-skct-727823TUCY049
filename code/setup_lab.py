# Swetha M — 727823TUCY049
# student_name: Swetha M
# roll_number: 727823TUCY049
# project_name: DockerSecurityScanner
# date: 2025-06-28

"""
setup_lab.py — Stage 1 of the Docker Security Scanner pipeline.

Responsibilities:
  1. Print roll number and timestamp.
  2. Verify Docker daemon is reachable.
  3. Install required Python dependencies.
  4. Pull a lightweight test image (alpine) for scanning demo.
  5. Spin up a deliberately misconfigured demo container.
"""

import subprocess
import sys
import datetime

ROLL_NUMBER = "727823TUCY049"
STUDENT_NAME = "Swetha M"

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run(cmd, check=True):
    print(f"[{ts()}] $ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip() and result.returncode != 0:
        print(f"[STDERR] {result.stderr.strip()}")
    if check and result.returncode != 0:
        print(f"[ERROR] Command failed (exit {result.returncode})")
        sys.exit(result.returncode)
    return result

def main():
    print("=" * 60)
    print(f"  SETUP LAB — Docker Security Scanner")
    print(f"  Roll Number : {ROLL_NUMBER}")
    print(f"  Timestamp   : {ts()}")
    print("=" * 60)

    # ── Step 1: Check Docker ─────────────────────────────────────
    print(f"\n[{ts()}] Step 1: Checking Docker daemon ...")
    result = run("docker info --format '{{.ServerVersion}}'", check=False)
    if result.returncode != 0:
        print(f"[{ts()}] [FAIL] Docker daemon not reachable.")
        print("        Start Docker with: sudo systemctl start docker")
        sys.exit(1)
    print(f"[{ts()}] [OK] Docker daemon is running (server version: {result.stdout.strip()})")

    # ── Step 2: Install Python dependencies ──────────────────────
    print(f"\n[{ts()}] Step 2: Installing Python dependencies ...")
    run("pip install docker==7.1.0 reportlab==4.2.0 --quiet --break-system-packages")
    print(f"[{ts()}] [OK] Dependencies installed.")

    # ── Step 3: Pull alpine image ─────────────────────────────────
    print(f"\n[{ts()}] Step 3: Pulling alpine image for scan demo ...")
    run("docker pull alpine:latest", check=False)
    print(f"[{ts()}] [OK] alpine:latest pulled.")

    # ── Step 4: Launch a deliberately misconfigured demo container ─
    print(f"\n[{ts()}] Step 4: Starting demo container (misconfigured for scanning) ...")
    # Remove if already exists
    run("docker rm -f dss_demo_container 2>/dev/null || true", check=False)
    run(
        "docker run -d --name dss_demo_container "
        "--privileged "            # intentional: triggers privileged check
        "-p 0.0.0.0:8888:80 "     # intentional: triggers exposed-port check
        "alpine:latest sleep 3600",
        check=False,
    )
    print(f"[{ts()}] [OK] Demo container 'dss_demo_container' is running.")

    print(f"\n[{ts()}] ─── Lab setup complete. Ready for scanning. ───")
    print(f"[{ts()}] Roll Number : {ROLL_NUMBER}")

if __name__ == "__main__":
    main()
