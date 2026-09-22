from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["message"] == "Log Anomaly Detector API is running"


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_analyze_log():
    with open("logs/server.log", "rb") as file:
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "server.log",
                    file,
                    "text/plain"
                )
            }
        )

    assert response.status_code == 200

    data = response.json()

    assert data["filename"] == "server.log"

    assert data["summary"]["total_errors"] == 8
    assert data["summary"]["total_warnings"] == 3
    assert data["summary"]["failed_login_events"] == 5
    assert data["summary"]["brute_force_incidents"] == 1
    assert data["summary"]["authentication_failures"] == 2

def test_analyze_rejects_non_log_file():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "test.txt",
                b"This is not a log file",
                "text/plain"
            )
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only .log files are supported"

def test_analyze_rejects_non_log_file():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "test.txt",
                b"This is not a log file",
                "text/plain"
            )
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only .log files are supported"