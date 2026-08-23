from typing import Dict, Any

from backend.models.security_event import SecurityEvent
from backend.models.security_event_db import SecurityEventDB


def analyze_event(event: SecurityEvent) -> Dict[str, Any]:
    """
    Analyze a security event and return a detection result.
    """

    risk_score = 0
    detections = []

    # Rule 1: Blocked SSH connection
    if (
        event.destination_port == 22
        and event.action == "blocked"
    ):
        risk_score += 30

        detections.append({
            "rule": "SSH_CONNECTION_BLOCKED",
            "description": "Blocked SSH connection attempt detected."
        })

    # Rule 2: High severity event
    if event.severity == "high":
        risk_score += 40

        detections.append({
            "rule": "HIGH_SEVERITY_EVENT",
            "description": "Event has been classified as high severity."
        })

    # Rule 3: Critical severity event
    if event.severity == "critical":
        risk_score += 60

        detections.append({
            "rule": "CRITICAL_SEVERITY_EVENT",
            "description": "Critical security event detected."
        })

    # Convert score into a risk level
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "detections": detections
    }
def detect_brute_force(event: SecurityEvent, previous_events: list) -> Dict[str, Any]:
    """
    Detect repeated SSH connection attempts from the same source IP.
    """

    if event.destination_port != 22:
        return {
            "detected": False,
            "attempt_count": 0
        }

    if not event.source_ip:
        return {
            "detected": False,
            "attempt_count": 0
        }

    ssh_attempts = [
        previous_event
        for previous_event in previous_events
        if previous_event.source_ip == event.source_ip
        and previous_event.destination_port == 22
    ]

    attempt_count = len(ssh_attempts) + 1

    if attempt_count >= 5:
        return {
            "detected": True,
            "attempt_count": attempt_count,
            "rule": "SSH_BRUTE_FORCE",
            "description": (
                f"Possible SSH brute-force attack from "
                f"{event.source_ip}: {attempt_count} attempts detected."
            )
        }

    return {
        "detected": False,
        "attempt_count": attempt_count
    }