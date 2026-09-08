"""Flask web dashboard for viewing and filtering Mini SIEM alerts.

Run with:
    python -m siem.app

Then open http://127.0.0.1:5000 in your browser.
"""

import os

from flask import Flask, render_template, request

from siem.alert_manager import alert_counts, fetch_alerts, init_db, save_alerts
from siem.detector import run_all_detectors
from siem.log_parser import parse_log_file

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
app = Flask(__name__, template_folder=os.path.join(PROJECT_ROOT, "templates"))

# Users considered "known" for the unknown-user detection rule.
# In a real deployment this would come from config or an identity source.
KNOWN_USERS = {"reddy", "admin", "deploy"}

SAMPLE_LOG_PATH = os.path.join(PROJECT_ROOT, "sample_logs", "sample_auth.log")


@app.route("/")
def dashboard():
    severity = request.args.get("severity") or None
    source_ip = request.args.get("source_ip") or None
    date = request.args.get("date") or None

    alerts = fetch_alerts(severity=severity, source_ip=source_ip, date=date)
    counts = alert_counts()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        counts=counts,
        filters={"severity": severity or "", "source_ip": source_ip or "", "date": date or ""},
    )


@app.route("/ingest", methods=["POST"])
def ingest():
    """Re-parse the sample log file and run detection, storing any new alerts.

    In a real deployment this would be triggered by a scheduler or a
    file-watcher rather than a manual button, but a manual trigger keeps
    the demo simple and easy to show in an interview.
    """
    events = parse_log_file(SAMPLE_LOG_PATH)
    alerts = run_all_detectors(events, KNOWN_USERS)
    inserted = save_alerts(alerts)
    return {"status": "ok", "events_parsed": len(events), "alerts_saved": inserted}


def main():
    init_db()
    app.run(debug=True)


if __name__ == "__main__":
    main()
