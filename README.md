# Mini SIEM — Log Analysis & Alert Dashboard 🛡️

A beginner-friendly Security Information and Event Management (SIEM) style tool that ingests system/auth logs, detects suspicious activity, and displays alerts on a simple dashboard. Built to simulate real SOC Analyst log-monitoring and triage workflows.

⚠️ **Educational Use Only**: Use this tool only on your own systems, test environments, or sample/synthetic log data.

## 🎯 Project Objective

The objective of this project is to build a lightweight, functional SIEM-style pipeline that mirrors the core responsibilities of a SOC Analyst: collecting logs, detecting anomalies, and surfacing actionable alerts.

The project focuses on:

- Understanding log formats and common attack signatures
- Parsing and analyzing authentication/system logs with Python
- Detecting brute-force attempts, failed logins, and unusual access patterns
- Building a simple alerting and severity-classification system
- Visualizing alerts on a lightweight web dashboard
- Practicing end-to-end security-tool development (ingestion → detection → visualization)

## ✨ Features

- Ingest log files (e.g., Linux `auth.log`, sample web server access logs, or synthetic sample logs)
- Detect repeated failed login attempts (brute-force pattern detection)
- Flag logins from unusual times or unfamiliar source IPs
- Detect basic port-scan signatures (can reuse logic from `python-vulnerability-scanner`)
- Classify alerts by severity (Low / Medium / High)
- Store alert history in a local database
- Display alerts on a simple web dashboard (timestamp, source IP, alert type, severity)
- Filter/search alerts by date, severity, or source IP

## 🛠️ Technologies Used

- Python 3
- Flask (lightweight dashboard/backend)
- SQLite (alert history storage)
- Regex / log parsing
- HTML/CSS (basic dashboard UI, minimal JS)
- Git and GitHub

## 📂 Suggested Project Structure

```
mini-siem/
├── siem/
│   ├── __init__.py
│   ├── log_parser.py        # Reads and parses raw log files
│   ├── detector.py          # Detection rules (brute-force, odd hours, etc.)
│   ├── alert_manager.py     # Creates, stores, and classifies alerts
│   └── app.py                # Flask app serving the dashboard
├── sample_logs/
│   └── sample_auth.log       # Synthetic/sample log data for testing
├── templates/
│   └── dashboard.html        # Dashboard UI
├── tests/
│   └── test_detector.py
├── README.md
├── requirements.txt
└── .gitignore
```

## 🚀 Suggested Build Order (Milestones)

1. **Log ingestion** — write a parser that reads a sample `auth.log` file line by line and extracts timestamp, source IP, and event type.
2. **Detection rules v1** — implement brute-force detection (e.g., 5+ failed logins from the same IP within 60 seconds).
3. **Alert storage** — save detected alerts to SQLite with severity and timestamp.
4. **Dashboard v1** — basic Flask page listing alerts in a table.
5. **Detection rules v2** — add unusual-time detection and basic port-scan signature matching.
6. **Dashboard v2** — add filtering by severity/date/IP, and simple counts (e.g., alerts today, high-severity count).
7. **Polish** — README, sample data, screenshots, and a short demo GIF for your GitHub repo.

## 🔬 Learning Outcomes

By completing this project, you'll be able to speak to:

- How SOC Analysts triage log data and identify indicators of compromise (IOCs)
- Practical experience with log parsing and pattern-based detection logic
- Basic full-stack skills applied to a security use case (Python backend + simple UI)
- How alert severity and prioritization works in a real SOC workflow

## 📌 Project Status

✅ Core Features Complete — log parsing, all three detection rules (brute-force, unusual-hour, unknown-user), SQLite alert storage, and the Flask dashboard (with filtering) are implemented and covered by a passing pytest suite (6/6 tests). Future improvements (email alerts, a scan scheduler, more detection rules) can be added incrementally on top of this working base.
