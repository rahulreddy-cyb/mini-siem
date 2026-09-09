"""Flask web dashboard for viewing and managing Mini SIEM alerts.

Run with:
    python -m siem.app

Then open http://127.0.0.1:5000 in your browser.
"""

import os

from flask import Flask, jsonify, render_template, request

from siem.alert_manager import (
    alert_counts,
    fetch_alerts,
    init_db,
    save_alerts,
    update_alert_status,
    update_analyst_note,
)
from siem.detector import run_all_detectors
from siem.log_parser import parse_log_file


PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "templates"),
)

# Users considered "known" for the unknown-user detection rule.
# In a real deployment this would come from config or an identity source.
KNOWN_USERS = {"reddy", "admin", "deploy"}

# Sample log is stored at the project root:
# ~/kali/sample_auth.log
SAMPLE_LOG_PATH = os.path.join(
    PROJECT_ROOT,
    "sample_auth.log",
)


@app.route("/")
def dashboard():
    """Display alerts with optional filtering."""
    severity = request.args.get("severity") or None
    source_ip = request.args.get("source_ip") or None
    date = request.args.get("date") or None

    alerts = fetch_alerts(
        severity=severity,
        source_ip=source_ip,
        date=date,
    )

    counts = alert_counts()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        counts=counts,
        filters={
            "severity": severity or "",
            "source_ip": source_ip or "",
            "date": date or "",
        },
    )


@app.route("/ingest", methods=["POST"])
def ingest():
    """Parse the sample log, run detection rules, and store alerts."""
    events = parse_log_file(SAMPLE_LOG_PATH)
    alerts = run_all_detectors(events, KNOWN_USERS)
    inserted = save_alerts(alerts)

    return jsonify(
        {
            "status": "ok",
            "events_parsed": len(events),
            "alerts_saved": inserted,
        }
    )


@app.route("/api/alerts/<int:alert_id>/status", methods=["PATCH"])
def change_alert_status(alert_id: int):
    """Update the lifecycle status of an alert."""
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().upper()

    allowed_statuses = {
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE",
    }

    if status not in allowed_statuses:
        return jsonify(
            {
                "status": "error",
                "message": (
                    "Invalid status. Allowed values: "
                    "NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE"
                ),
            }
        ), 400

    try:
        updated = update_alert_status(
            alert_id=alert_id,
            status=status,
        )
    except ValueError as exc:
        return jsonify(
            {
                "status": "error",
                "message": str(exc),
            }
        ), 400

    if not updated:
        return jsonify(
            {
                "status": "error",
                "message": f"Alert {alert_id} not found.",
            }
        ), 404

    return jsonify(
        {
            "status": "ok",
            "alert_id": alert_id,
            "new_status": status,
        }
    )


@app.route("/api/alerts/<int:alert_id>/note", methods=["PATCH"])
def change_analyst_note(alert_id: int):
    """Save or update the analyst note for an alert."""
    data = request.get_json(silent=True) or {}
    note = data.get("note", "")

    if not isinstance(note, str):
        return jsonify(
            {
                "status": "error",
                "message": "Analyst note must be a string.",
            }
        ), 400

    updated = update_analyst_note(
        alert_id=alert_id,
        note=note.strip(),
    )

    if not updated:
        return jsonify(
            {
                "status": "error",
                "message": f"Alert {alert_id} not found.",
            }
        ), 404

    return jsonify(
        {
            "status": "ok",
            "alert_id": alert_id,
            "analyst_note": note.strip(),
        }
    )


def main():
    """Initialize the database and start the Flask application."""
    init_db()
    app.run(debug=True)


if __name__ == "__main__":
    main()
