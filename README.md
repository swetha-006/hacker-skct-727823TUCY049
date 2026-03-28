# Docker Security Scanner

| Field | Detail |
|---|---|
| **Student** | Swetha M |
| **Roll Number** | 727823TUCY049 |
| **Project** | DockerSecurityScanner |
| **Category** | Security Automation / Docker Hardening |
| **GitHub Repo** | hacker-skct-727823TUCY049 |

---

## What This Tool Does

Docker Security Scanner is a Python-based command-line tool that audits a local Docker environment for common security misconfigurations. In a single scan it checks running containers for privileged mode, root user execution, unbound port exposure, and missing resource limits, while also auditing local images for age and missing tags. Results are written as structured JSON files and analysed in a human-readable severity table.

---

## Lab Environment

- **Host OS:** Kali Linux 2024.x (VirtualBox VM)
- **Target:** Local Docker daemon (Docker Engine 26+)
- **Test images/containers:** alpine:latest (deliberately misconfigured)
- **Python:** 3.11+

---

## Tools & Dependencies

| Tool | Purpose |
|---|---|
| `docker` (SDK) | Connect to Docker daemon, inspect containers/images |
| `reportlab` | Generate PDF report |
| Python stdlib (`argparse`, `json`, `datetime`, `subprocess`) | Argument parsing, output handling |

Install with:

```bash
pip install -r requirements.txt
```

---

## Setup Steps

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/hacker-skct-727823TUCY049.git
cd hacker-skct-727823TUCY049

# 2. Install dependencies
pip install -r requirements.txt

# 3. Make sure Docker is running
sudo systemctl start docker

# 4. Run the full pipeline
python3 code/setup_lab.py
python3 code/run_tool.py
python3 code/analyze_results.py
```

---

## Usage Examples

```bash
# Full scan (containers + images, all severities)
python3 code/tool_main.py --mode full --tc 1

# Containers only, HIGH severity issues only
python3 code/tool_main.py --mode containers --severity HIGH --tc 2

# Images only (age and tag audit)
python3 code/tool_main.py --mode images --tc 3
```

---

## Project Structure

```
SKCT_727823TUCY049_DockerSecurityScanner/
├── code/
│   ├── tool_main.py            ← Primary scanner
│   ├── setup_lab.py            ← Pipeline Stage 1
│   ├── run_tool.py             ← Pipeline Stage 2
│   ├── analyze_results.py      ← Pipeline Stage 3
│   └── helper_modules/
│       └── report_utils.py     ← Shared utilities
├── notebooks/
│   └── demo.ipynb              ← Live demo notebook
├── screenshots/                ← Test case terminal screenshots
├── report/
│   └── report.pdf              ← 2-page submission report
├── pipeline_727823TUCY049.yml  ← Pipeline definition
├── requirements.txt
├── README.md
└── submission_form.txt
```

---

## Test Cases

| TC | Mode | Severity Filter | What It Demonstrates |
|---|---|---|---|
| TC1 | `full` | ALL | Complete scan — containers and images |
| TC2 | `containers` | HIGH | Filters to only critical issues (privileged, root) |
| TC3 | `images` | ALL | Image-only audit — age and dangling tag detection |

---

## Ethical Considerations

All scanning was performed exclusively on containers and images running on a personally owned virtual machine. No external hosts, production systems, or third-party infrastructure were targeted. The tool is designed for defensive security auditing of environments under the user's own control.
