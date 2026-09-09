"""Parses raw auth-log style log files into structured events.

Expected sample log line format (synthetic, similar to Linux auth.log):

    2026-09-08 03:14:02 sshd[1234]: Failed password for admin from 192.168.1.50 port 51423 ssh2
    2026-09-08 03:14:05 sshd[1234]: Accepted password for reddy from 192.168.1.10 port 51500 ssh2
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


LOG_LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<process>\w+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass
class LogEvent:
    """A single structured event parsed from a log line."""

    timestamp: datetime
    process: str
    status: str  # "Failed" or "Accepted"
    user: str
    source_ip: str
    port: int
    raw_line: str


def parse_line(line: str) -> Optional[LogEvent]:
    """Parse a single raw log line into a LogEvent, or None if it doesn't match."""
    match = LOG_LINE_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    return LogEvent(
        timestamp=datetime.strptime(data["timestamp"], TIMESTAMP_FORMAT),
        process=data["process"],
        status=data["status"],
        user=data["user"],
        source_ip=data["source_ip"],
        port=int(data["port"]),
        raw_line=line.strip(),
    )


def parse_log_file(file_path: str) -> List[LogEvent]:
    """Read a log file and return a list of successfully parsed LogEvents.

    Lines that don't match the expected pattern are skipped silently,
    so this tolerates blank lines or unrelated log entries mixed in.
    """
    events: List[LogEvent] = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = parse_line(line)
            if event:
                events.append(event)
    return events
