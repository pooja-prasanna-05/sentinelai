from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    timestamp: datetime

    source: str = Field(
        description="Origin of the security event"
    )

    event_type: str = Field(
        description="Type of security event"
    )

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    username: Optional[str] = None

    action: Optional[str] = None

    severity: Optional[str] = "unknown"

    message: Optional[str] = None