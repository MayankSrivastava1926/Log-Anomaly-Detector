# Log File Anomaly Detector

A Python-based security tool that analyzes server log files and detects suspicious activities, authentication failures, resource anomalies, and potential brute-force attacks.

## 🚀 Live Demo

**API:** https://log-anomaly-detector-6nqp.onrender.com/

**Swagger API Docs:** https://log-anomaly-detector-6nqp.onrender.com/docs

## Features

- Log file parsing
- Error and warning counting
- Failed login detection
- Brute-force attack detection
- Rapid login detection
- Login burst detection
- Multiple users targeted from the same IP detection
- CPU usage monitoring
- Disk usage monitoring
- Memory usage detection
- Authentication failure detection
- Severity classification
- Attack/behavior classification
- Malformed log handling
- Missing file validation
- Command-line interface
- TXT report generation
- JSON report generation
- FastAPI REST API
- SQLite scan history
- Scan history retrieval
- Individual scan retrieval
- Automated testing with pytest

## Project Structure

```text
Log Anomaly Detector/
│
├── api/
│   └── main.py
│
├── database/
│   ├── __init__.py
│   ├── database.py
│   ├── init_db.py
│   └── models.py
│
├── logs/
│   ├── sample.log
│   └── server.log
│
├── output/
│   ├── anomaly_report.txt
│   ├── anomaly_report.json
│   └── server_report.txt
│
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── detect_anomalies.py
│   ├── json_report.py
│   ├── report.py
│   └── ...
│
├── tests/
│   ├── test_detector.py
│   └── test_api.py
│
├── .gitignore
├── README.md
└── anomaly_detector.db