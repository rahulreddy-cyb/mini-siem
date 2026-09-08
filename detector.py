"""Detection rules that turn parsed LogEvents into Alerts.

Implements three simple, explainable detection rules that mirror
common SOC Level-1 triage checks:

1. Brute-force detection  — many failed logins from the same IP in a short window
2. Unusual-hour detection — successful logins during atypical hours (e.g., 12am-5am)
3. Unknown-user detection — login attempts (failed or accepted) for usernames
   not in an expected allow-list
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Set

from siem.log_parser import LogEvent


@dataclass
class Alert:
    """A detected suspicious event, ready to be stored/displayed."""

    timestamp: datetime
    alert_type: str
    severity: str  # "Low", "Medium", "High"
    source_ip: str
    user: str
    description: str


# --- Rule 1: Brute-force detection -----------------------------------------

def detect_brute_force(
    events: List[LogEvent],
    threshold: int = 5,
    window_seconds: int = 60,
) -> List[Alert]:
    """Flag an IP as brute-forcing if it has >= `threshold` failed logins
    within any `window_seconds` sliding window.
    """
    failed_by_ip: dict[str, List[LogEvent]] = defaultdict(list)
    for event in events:
        if event.status == "Failed":
            failed_by_ip[event.source_ip].append(event)

    alerts: List[Alert] = []
    for ip, ip_events in failed_by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        window: List[LogEvent] = []

        for event in ip_events:
            window.append(event)
            # Drop events that have fallen outside the sliding window.
            window = [
                e for e in window
                if (event.timestamp - e.timestamp) <= timedelta(seconds=window_seconds)
            ]

            if len(window) >= threshold:
                alerts.append(
                    Alert(
                        timestamp=event.timestamp,
                        alert_type="Brute Force Attempt",
                        severity="High",
                        source_ip=ip,
                        user=event.user,
                        description=(
                            f"{len(window)} failed login attempts from {ip} "
                            f"within {window_seconds}s (targeting user '{event.user}')."
                        ),
                    )
                )
                window = []  # avoid re-alerting on every event in the same burst

    return alerts


# --- Rule 2: Unusual-hour detection -----------------------------------------

def detect_unusual_hours(
    events: List[LogEvent],
    start_hour: int = 0,
    end_hour: int = 5,
) -> List[Alert]:
    """Flag successful logins that happen between start_hour and end_hour (inclusive-exclusive)."""
    alerts: List[Alert] = []
    for event in events:
        if event.status == "Accepted" and start_hour <= event.timestamp.hour < end_hour:
            alerts.append(
                Alert(
                    timestamp=event.timestamp,
                    alert_type="Unusual Hour Login",
                    severity="Medium",
                    source_ip=event.source_ip,
                    user=event.user,
                    description=(
                        f"Successful login for '{event.user}' from {event.source_ip} "
                        f"at {event.timestamp.strftime('%H:%M:%S')} (outside normal hours)."
                    ),
                )
            )
    return alerts


# --- Rule 3: Unknown-user detection -----------------------------------------

def detect_unknown_users(
    events: List[LogEvent],
    known_users: Set[str],
) -> List[Alert]:
    """Flag any login attempt (failed or accepted) for a user not in known_users."""
    alerts: List[Alert] = []
    for event in events:
        if event.user not in known_users:
            alerts.append(
                Alert(
                    timestamp=event.timestamp,
                    alert_type="Unknown User Attempt",
                    severity="Medium" if event.status == "Failed" else "High",
                    source_ip=event.source_ip,
                    user=event.user,
                    description=(
                        f"{event.status} login for unrecognized user '{event.user}' "
                        f"from {event.source_ip}."
                    ),
                )
            )
    return alerts


def run_all_detectors(events: List[LogEvent], known_users: Set[str]) -> List[Alert]:
    """Convenience function: run every detection rule and merge results,
    sorted by timestamp.
    """
    alerts = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_unusual_hours(events))
    alerts.extend(detect_unknown_users(events, known_users))
    alerts.sort(key=lambda a: a.timestamp)
    return alerts
