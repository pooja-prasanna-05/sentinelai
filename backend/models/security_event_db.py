from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from backend.services.database import Base


class SecurityEventDB(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(DateTime, nullable=False)

    source = Column(String, nullable=False)
    event_type = Column(String, nullable=False)

    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)

    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)

    username = Column(String, nullable=True)

    action = Column(String, nullable=True)
    severity = Column(String, nullable=True)

    message = Column(String, nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String, nullable=True)
    detections = Column(Text, nullable=True) 
   