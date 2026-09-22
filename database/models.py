from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime, timezone

from database.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    filename = Column(String, nullable=False)

    total_errors = Column(Integer, default=0)
    total_warnings = Column(Integer, default=0)

    critical_alerts = Column(Integer, default=0)
    high_alerts = Column(Integer, default=0)
    medium_alerts = Column(Integer, default=0)

    failed_login_events = Column(Integer, default=0)
    brute_force_incidents = Column(Integer, default=0)
    authentication_failures = Column(Integer, default=0)

    alerts = Column(Text, nullable=True)

    created_at = Column(
    DateTime,
    default=lambda: datetime.now(timezone.utc)
)