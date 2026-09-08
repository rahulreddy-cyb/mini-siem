"""Unit tests for detection rules. Run with: pytest"""

from datetime import datetime

from siem.detector import detect_brute_force, detect_unusual_hours, detect_unknown_users
from siem.log_parser import LogEvent


def make_event(hour, minute, second, status, user, ip, port=50000):
    return LogEvent(
        timestamp=datetime(2026, 9, 8, hour, minute, second),
        process="sshd",
        status=status,
        user=user,
        source_ip=ip,
        port=port,
        raw_line="",
    )


def test_detect_brute_force_flags_rapid_failures():
    events = [
        make_event(2, 10, i, "Failed", "admin", "203.0.113.42")
        for i in range(0, 6, 1)  # 6 failed attempts, 1 second apart
    ]
    alerts = detect_brute_force(events, threshold=5, window_seconds=60)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "Brute Force Attempt"
    assert alerts[0].severity == "High"


def test_detect_brute_force_ignores_slow_failures():
    # Failures spaced far apart shouldn't trigger the sliding-window rule.
    events = [
        make_event(2, m, 0, "Failed", "admin", "203.0.113.42")
        for m in range(0, 30, 5)  # every 5 minutes
    ]
    alerts = detect_brute_force(events, threshold=5, window_seconds=60)
    assert len(alerts) == 0


def test_detect_unusual_hours_flags_late_night_login():
    events = [make_event(3, 0, 0, "Accepted", "reddy", "192.168.1.10")]
    alerts = detect_unusual_hours(events, start_hour=0, end_hour=5)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "Unusual Hour Login"


def test_detect_unusual_hours_ignores_daytime_login():
    events = [make_event(14, 0, 0, "Accepted", "reddy", "192.168.1.10")]
    alerts = detect_unusual_hours(events, start_hour=0, end_hour=5)
    assert len(alerts) == 0


def test_detect_unknown_users_flags_unrecognized_username():
    events = [make_event(9, 0, 0, "Failed", "hacker123", "198.51.100.5")]
    alerts = detect_unknown_users(events, known_users={"reddy", "admin"})
    assert len(alerts) == 1
    assert alerts[0].user == "hacker123"


def test_detect_unknown_users_ignores_known_username():
    events = [make_event(9, 0, 0, "Accepted", "reddy", "192.168.1.10")]
    alerts = detect_unknown_users(events, known_users={"reddy", "admin"})
    assert len(alerts) == 0
