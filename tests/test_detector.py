import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DETECTOR = PROJECT_ROOT / "src" / "detect_anomalies.py"


def run_detector(log_file, output_file):
    return subprocess.run(
        [
            sys.executable,
            str(DETECTOR),
            "--log",
            str(log_file),
            "--output",
            str(output_file)
        ],
        capture_output=True,
        text=True
    )


def test_detector_runs_successfully(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 INFO User logged in\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0
    assert output_file.exists()


def test_failed_login_detection(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "Failed Login Events: 1" in report
    assert "[CRITICAL] [BRUTE FORCE ATTACK]" in report


def test_cpu_threshold(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 WARNING "
        "CPU usage reached 95%\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "[HIGH] [RESOURCE EXHAUSTION]" in report


def test_cpu_below_threshold(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 WARNING "
        "CPU usage reached 85%\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "[HIGH] [RESOURCE EXHAUSTION]" not in report


def test_disk_threshold(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 WARNING "
        "Disk usage reached 95%\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "[HIGH] [RESOURCE EXHAUSTION]" in report


def test_malformed_log_line(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "THIS IS A MALFORMED LOG LINE\n"
        "2026-08-06 10:15:00 INFO User logged in\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0
    assert "Skipping malformed log line" in result.stdout
    assert output_file.exists()


def test_missing_log_file(tmp_path):
    log_file = tmp_path / "does_not_exist.log"
    output_file = tmp_path / "report.txt"

    result = run_detector(log_file, output_file)

    assert result.returncode != 0
    assert "Log file not found" in result.stdout


def test_authentication_failure(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 ERROR "
        "Service authentication failed\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "AUTHENTICATION FAILURE" in report
    assert "Authentication Failures: 1" in report

def test_brute_force_incident(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:10 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:20 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "Failed Login Events: 3" in report
    assert "Brute Force Incidents: 1" in report
    assert "admin has 3 failed login attempts" in report

def test_rapid_login_detection(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:20 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "--- Rapid Login Detection ---" in report
    assert "admin had rapid failed login attempts" in report

def test_login_burst_detection(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:10 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:20 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:30 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:40 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "--- Login Burst Detection ---" in report
    assert "IP 192.168.1.15 generated 5 failed login attempts" in report

def test_multiple_users_same_ip(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"

    log_file.write_text(
        "2026-08-06 10:15:00 ERROR "
        "Failed login attempt for user 'admin' "
        "from 192.168.1.15\n"
        "2026-08-06 10:15:10 ERROR "
        "Failed login attempt for user 'rahul' "
        "from 192.168.1.15\n"
    )

    result = run_detector(log_file, output_file)

    assert result.returncode == 0

    report = output_file.read_text()

    assert "SUSPICIOUS IP ACTIVITY" in report
    assert "IP 192.168.1.15 targeted multiple users" in report
    assert "admin, rahul" in report

def test_json_report_generation(tmp_path):
    log_file = tmp_path / "test.log"
    output_file = tmp_path / "report.txt"
    json_file = tmp_path / "report.json"

    log_file.write_text(
        "2026-08-06 10:15:00 ERROR "
        "Service authentication failed\n"
    )

    result = subprocess.run(
        [
            sys.executable,
            str(DETECTOR),
            "--log",
            str(log_file),
            "--output",
            str(output_file),
            "--json-output",
            str(json_file)
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert json_file.exists()

    import json

    data = json.loads(json_file.read_text())

    assert "summary" in data
    assert "alerts" in data
    assert "rapid_login_detection" in data
    assert "login_burst_detection" in data

    assert data["summary"]["total_errors"] == 1
    assert data["summary"]["authentication_failures"] == 1