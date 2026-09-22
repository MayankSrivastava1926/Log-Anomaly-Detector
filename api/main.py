from io import StringIO
from typing import List

from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel

from src.detect_anomalies import (
    process_log_file,
    detect_brute_force,
    detect_multiple_users,
    detect_rapid_logins,
    detect_login_bursts,
    build_final_report
)

from database.database import SessionLocal, engine, Base
from database.models import Scan


app = FastAPI(
    title="Log Anomaly Detector API",
    description="REST API for log anomaly detection",
    version="1.0.0"
)


Base.metadata.create_all(bind=engine)


class Summary(BaseModel):
    total_errors: int
    total_warnings: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    failed_login_events: int
    brute_force_incidents: int
    authentication_failures: int


class AnalyzeResponse(BaseModel):
    filename: str
    summary: Summary
    alerts: List[str]
    rapid_login_detection: List[str]
    login_burst_detection: List[str]
    report: List[str]


@app.get("/")
def root():
    return {
        "message": "Log Anomaly Detector API is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

@app.get("/scans")
def get_scans():
    db = SessionLocal()

    try:
        scans = (
            db.query(Scan)
            .order_by(Scan.created_at.desc())
            .all()
        )

        return [
            {
                "id": scan.id,
                "filename": scan.filename,
                "total_errors": scan.total_errors,
                "total_warnings": scan.total_warnings,
                "critical_alerts": scan.critical_alerts,
                "high_alerts": scan.high_alerts,
                "medium_alerts": scan.medium_alerts,
                "failed_login_events": scan.failed_login_events,
                "brute_force_incidents": scan.brute_force_incidents,
                "authentication_failures": scan.authentication_failures,
                "created_at": scan.created_at
            }
            for scan in scans
        ]

    finally:
        db.close()

@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    db = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if not scan:
            raise HTTPException(
                status_code=404,
                detail="Scan not found"
            )

        return {
            "id": scan.id,
            "filename": scan.filename,
            "total_errors": scan.total_errors,
            "total_warnings": scan.total_warnings,
            "critical_alerts": scan.critical_alerts,
            "high_alerts": scan.high_alerts,
            "medium_alerts": scan.medium_alerts,
            "failed_login_events": scan.failed_login_events,
            "brute_force_incidents": scan.brute_force_incidents,
            "authentication_failures": scan.authentication_failures,
            "alerts": scan.alerts.split("\n") if scan.alerts else [],
            "created_at": scan.created_at
        }

    finally:
        db.close()

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_log(file: UploadFile = File(...)):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required"
        )

    if not file.filename.lower().endswith(".log"):
        raise HTTPException(
            status_code=400,
            detail="Only .log files are supported"
        )

    try:
        content = await file.read()

        text = content.decode("utf-8")

        log_file = StringIO(text)

        (
            report,
            failed_logins,
            ip_failed_logins,
            ip_users,
            user_login_times,
            ip_login_times,
            total_errors,
            total_warnings,
            critical_alerts,
            high_alerts,
            medium_alerts,
            failed_login_events,
            authentication_failures
        ) = process_log_file(log_file)

        # --------------------------------------------------
        # BRUTE FORCE
        # --------------------------------------------------

        brute_force_alerts, brute_force_incidents = (
            detect_brute_force(
                report,
                failed_logins,
                ip_failed_logins
            )
        )

        # --------------------------------------------------
        # MULTIPLE USERS FROM SAME IP
        # --------------------------------------------------

        multiple_user_alerts = detect_multiple_users(
            report,
            ip_users
        )

        # --------------------------------------------------
        # RAPID LOGIN
        # --------------------------------------------------

        rapid_report, rapid_alerts = detect_rapid_logins(
            user_login_times
        )

        # --------------------------------------------------
        # LOGIN BURST
        # --------------------------------------------------

        burst_report, burst_alerts = detect_login_bursts(
            ip_login_times
        )

        # --------------------------------------------------
        # TOTAL CRITICAL ALERTS
        # --------------------------------------------------

        critical_alerts = (
            critical_alerts
            + brute_force_alerts
            + multiple_user_alerts
            + rapid_alerts
            + burst_alerts
        )

        # --------------------------------------------------
        # BUILD FINAL REPORT
        # --------------------------------------------------

        final_report = build_final_report(
            report,
            rapid_report,
            burst_report,
            total_errors,
            total_warnings,
            critical_alerts,
            high_alerts,
            medium_alerts,
            failed_login_events,
            brute_force_incidents,
            authentication_failures
        )

        # --------------------------------------------------
        # SUMMARY
        # --------------------------------------------------

        summary = {
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "failed_login_events": failed_login_events,
            "brute_force_incidents": brute_force_incidents,
            "authentication_failures": authentication_failures
        }

        # --------------------------------------------------
        # SAVE SCAN TO DATABASE
        # --------------------------------------------------

        db = SessionLocal()

        try:
            scan = Scan(
                filename=file.filename,
                total_errors=total_errors,
                total_warnings=total_warnings,
                critical_alerts=critical_alerts,
                high_alerts=high_alerts,
                medium_alerts=medium_alerts,
                failed_login_events=failed_login_events,
                brute_force_incidents=brute_force_incidents,
                authentication_failures=authentication_failures,
                alerts="\n".join(final_report)
            )

            db.add(scan)
            db.commit()
            db.refresh(scan)

        finally:
            db.close()

        # --------------------------------------------------
        # RESPONSE
        # --------------------------------------------------

        return {
            "filename": file.filename,
            "summary": summary,
            "alerts": report,
            "rapid_login_detection": rapid_report,
            "login_burst_detection": burst_report,
            "report": final_report
        }

    except UnicodeDecodeError:

        raise HTTPException(
            status_code=400,
            detail="Log file must be UTF-8 encoded"
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )