\# Log File Anomaly Detector



A Python-based security tool that analyzes server log files and detects suspicious activities, authentication failures, resource anomalies, and potential brute-force attacks.



\## Features



\- Log file parsing

\- Error and warning counting

\- Failed login detection

\- Brute-force attack detection

\- Rapid login detection

\- Login burst detection

\- Multiple users targeted from the same IP detection

\- CPU usage monitoring

\- Disk usage monitoring

\- Memory usage detection

\- Authentication failure detection

\- Severity classification

\- Attack/behavior classification

\- Malformed log handling

\- Missing file validation

\- Command-line interface

\- TXT report generation

\- JSON report generation

\- Automated testing with pytest



\## Project Structure



```text

Log Anomaly Detector/

│

├── logs/

│   ├── sample.log

│   └── server.log

│

├── output/

│   ├── anomaly\_report.txt

│   ├── anomaly\_report.json

│   └── server\_report.txt

│

├── src/

│   ├── config.py

│   ├── detect\_anomalies.py

│   ├── json\_report.py

│   ├── report.py

│   └── ...

│

├── tests/

│   └── test\_detector.py

│

└── README.md



