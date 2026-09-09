"""Detection rules that turn parsed LogEvents into Alerts.

Implements four simple, explainable detection rules that mirror
common SOC Level-1 triage checks:

1. Brute-force detection
   Many failed logins from the same IP in a short window.

2. Unusual-hour detection
   Successful logins during atypical hours (e.g., 12am-5am).

3. Unknown-user detection
   Login attempts (failed or accepted) for usernames
   not in an expected allow-list.

4. Anomalous multi-IP login detection
   Successful logins for the same account from different source IPs
   within a short time window.
"""

from collections import defaultdict
from dataclasses import dataclass
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

            # Drop events outside the sliding window.
            window = [
                e
                for e in window
                if (event.timestamp - e.timestamp)
                <= timedelta(seconds=window_seconds)
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
                            f"within {window_seconds}s "
                            f"(targeting user '{event.user}')."
                        ),
                    )
                )

                # Avoid re-alerting on every event in the same burst.
                window = []

    return alerts


# --- Rule 2: Unusual-hour detection -----------------------------------------


def detect_unusual_hours(
    events: List[LogEvent],
    start_hour: int = 0,
    end_hour: int = 5,
) -> List[Alert]:
    """Flag successful logins between start_hour and end_hour."""
    alerts: List[Alert] = []

    for event in events:
        if (
            event.status == "Accepted"
            and start_hour <= event.timestamp.hour < end_hour
        ):
            alerts.append(
                Alert(
                    timestamp=event.timestamp,
                    alert_type="Unusual Hour Login",
                    severity="Medium",
                    source_ip=event.source_ip,
                    user=event.user,
                    description=(
                        f"Successful login for '{event.user}' "
                        f"from {event.source_ip} at "
                        f"{event.timestamp.strftime('%H:%M:%S')} "
                        f"(outside normal hours)."
                    ),
                )
            )

    return alerts


# --- Rule 3: Unknown-user detection -----------------------------------------


def detect_unknown_users(
    events: List[LogEvent],
    known_users: Set[str],
) -> List[Alert]:
    """Flag login attempts for users not in known_users."""
    alerts: List[Alert] = []

    for event in events:
        if event.user not in known_users:
            alerts.append(
                Alert(
                    timestamp=event.timestamp,
                    alert_type="Unknown User Attempt",
                    severity=(
                        "Medium"
                        if event.status == "Failed"
                        else "High"
                    ),
                    source_ip=event.source_ip,
                    user=event.user,
                    description=(
                        f"{event.status} login for unrecognized user "
                        f"'{event.user}' from {event.source_ip}."
                    ),
                )
            )

    return alerts


# --- Rule 4: Anomalous multi-IP login detection -----------------------------


def detect_multi_ip_logins(
    events: List[LogEvent],
    window_minutes: int = 10,
) -> List[Alert]:
    """Flag successful logins for the same account from different IPs
    within a short time window.

    This is intentionally called anomalous multi-IP login detection
    rather than impossible-travel detection because the rule does not
    use geographic/IP-location data.
    """
    accepted_by_user: dict[str, List[LogEvent]] = defaultdict(list)

    for event in events:
        if event.status == "Accepted":
            accepted_by_user[event.user].append(event)

    alerts: List[Alert] = []
    window = timedelta(minutes=window_minutes)

    for user, user_events in accepted_by_user.items():
        user_events.sort(key=lambda e: e.timestamp)

        for index, current_event in enumerate(user_events):
            previous_events = user_events[:index]

            for previous_event in previous_events:
                time_difference = (
                    current_event.timestamp - previous_event.timestamp
                )

                # Stop checking once the previous event is too old.
                if time_difference > window:
                    continue

                # Same user, different source IPs, short time window.
                if previous_event.source_ip != current_event.source_ip:
                    alerts.append(
                        Alert(
                            timestamp=current_event.timestamp,
                            alert_type="Anomalous Multi-IP Login",
                            severity="High",
                            source_ip=current_event.source_ip,
                            user=user,
                            description=(
                                f"User '{user}' logged in successfully from "
                                f"{previous_event.source_ip} and "
                                f"{current_event.source_ip} within "
                                f"{window_minutes} minutes."
                            ),
                        )
                    )

                    # One alert per current login event is enough.
                    break

    return alerts


# --- Run all detection rules -----------------------------------------------


def run_all_detectors(
    events: List[LogEvent],
    known_users: Set[str],
) -> List[Alert]:
    """Run every detection rule and return alerts sorted by timestamp."""

    alerts: List[Alert] = []

    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_unusual_hours(events))
    alerts.extend(detect_unknown_users(events, known_users))
    alerts.extend(detect_multi_ip_logins(events))

    alerts.sort(key=lambda a: a.timestamp)

    return alerts
