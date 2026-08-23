import json

from fastapi import FastAPI

from backend.models.security_event import SecurityEvent
from backend.models.security_event_db import SecurityEventDB
from backend.services.database import Base, engine, SessionLocal
from backend.services.detection_engine import analyze_event, detect_brute_force


app = FastAPI(
    title="SentinelAI",
    description="AI-powered Security Operations Center",
    version="0.1.0"
)


# Create database tables
Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------
# ROOT ENDPOINT
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "project": "SentinelAI",
        "status": "online",
        "version": "0.1.0"
    }


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ---------------------------------------------------------
# INGEST SECURITY EVENT
# ---------------------------------------------------------

@app.post("/events")
def ingest_event(event: SecurityEvent):

    # 1. Analyze the incoming event using the detection engine
    detection_result = analyze_event(event)

    # 2. Open database session
    db = SessionLocal()

    try:

        # 3. Get previous events for brute-force detection
        previous_events = db.query(SecurityEventDB).all()

        # 4. Run brute-force detection
        brute_force_result = detect_brute_force(
            event,
            previous_events
        )

        # 5. If brute-force activity is detected,
        #    increase the risk score
        if brute_force_result.get("detected", False):

            detection_result["risk_score"] = min(
                int(detection_result.get("risk_score", 0)) + 50,
                100
            )

            detection_result["risk_level"] = "high"

            detection_result["detections"].append({
                "rule": brute_force_result.get(
                    "rule",
                    "SSH_BRUTE_FORCE"
                ),
                "description": brute_force_result.get(
                    "description",
                    f"Possible SSH brute-force attack from "
                    f"{event.source_ip}."
                )
            })

        # 6. Create database event
        db_event = SecurityEventDB(
            timestamp=event.timestamp,
            source=event.source,
            event_type=event.event_type,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            username=event.username,
            action=event.action,
            severity=event.severity,
            message=event.message,
            risk_score=detection_result["risk_score"],
            risk_level=detection_result["risk_level"],
            detections=json.dumps(
                detection_result["detections"]
            )
        )

        # 7. Store event
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        # 8. Return result
        return {
            "status": "stored",
            "event_id": db_event.id,
            "detection": detection_result
        }

    finally:
        # Always close the database connection
        db.close()


# ---------------------------------------------------------
# GET ALL SECURITY EVENTS
# ---------------------------------------------------------

@app.get("/events")
def get_events():

    db = SessionLocal()

    try:

        # Get newest events first
        events = (
            db.query(SecurityEventDB)
            .order_by(SecurityEventDB.id.desc())
            .all()
        )

        result = []

        for event in events:

            result.append({
                "id": event.id,
                "timestamp": event.timestamp,
                "source": event.source,
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "source_port": event.source_port,
                "destination_port": event.destination_port,
                "username": event.username,
                "action": event.action,
                "severity": event.severity,
                "message": event.message,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
                "detections": (
                    json.loads(event.detections)
                    if event.detections
                    else []
                )
            })

        return result

    finally:
        db.close()