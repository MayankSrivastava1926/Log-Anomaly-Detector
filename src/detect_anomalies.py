from datetime import datetime
import argparse
import sys
import re


try:
    from src.config import (
        FAILED_LOGIN_THRESHOLD,
        RAPID_LOGIN_THRESHOLD,
        BURST_LOGIN_THRESHOLD,
        BURST_LOGIN_WINDOW,
        CPU_THRESHOLD,
        DISK_THRESHOLD
    )

    from src.report import save_report
    from src.json_report import save_json_report

except ModuleNotFoundError:
    from config import (
        FAILED_LOGIN_THRESHOLD,
        RAPID_LOGIN_THRESHOLD,
        BURST_LOGIN_THRESHOLD,
        BURST_LOGIN_WINDOW,
        CPU_THRESHOLD,
        DISK_THRESHOLD
    )

    from report import save_report
    from json_report import save_json_report


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def get_severity(message):
    message_lower = message.lower()

    if "failed login" in message_lower:
        return "CRITICAL"
    elif "invalid password" in message_lower:
        return "HIGH"
    elif "cpu usage" in message_lower:
        return "HIGH"
    elif "disk usage" in message_lower:
        return "HIGH"
    elif "memory" in message_lower:
        return "HIGH"
    elif "database connection failed" in message_lower:
        return "MEDIUM"
    elif "authentication failed" in message_lower:
        return "MEDIUM"
    else:
        return "LOW"


def classify_attack(message):
    message_lower = message.lower()

    if "failed login" in message_lower:
        return "BRUTE FORCE ATTACK"
    elif "targeted" in message_lower:
        return "SUSPICIOUS IP ACTIVITY"
    elif (
        "cpu usage" in message_lower
        or "memory" in message_lower
        or "disk usage" in message_lower
    ):
        return "RESOURCE EXHAUSTION"
    elif (
        "invalid password" in message_lower
        or "authentication failed" in message_lower
    ):
        return "AUTHENTICATION FAILURE"
    elif "database connection failed" in message_lower:
        return "DATABASE FAILURE"
    else:
        return "GENERAL ERROR"


# ==================================================
# COMMAND LINE ARGUMENTS
# ==================================================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Log File Anomaly Detector"
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to the log file"
    )

    parser.add_argument(
        "--output",
        default="output/anomaly_report.txt",
        help="Path for the anomaly report"
    )

    parser.add_argument(
        "--json-output",
        default=None,
        help="Optional path for the JSON report"
    )

    return parser.parse_args()


# ==================================================
# OPEN LOG FILE
# ==================================================

def open_log_file(log_file):

    try:
        return open(log_file, "r")

    except FileNotFoundError:
        print("ERROR: Log file not found:", log_file)
        sys.exit(1)

    except OSError as error:
        print("ERROR: Could not open log file:", error)
        sys.exit(1)


# ==================================================
# PROCESS LOG FILE
# ==================================================

def process_log_file(file):

    failed_logins = {}
    ip_failed_logins = {}
    ip_users = {}

    user_login_times = {}
    ip_login_times = {}

    report = []

    total_errors = 0
    total_warnings = 0

    high_alerts = 0
    medium_alerts = 0

    failed_login_events = 0
    authentication_failures = 0

    timestamp_pattern = (
        r"^\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2}"
    )

    for line_number, line in enumerate(file, start=1):

        line = line.strip()

        if not line:
            continue

        # --------------------------------------------------
        # MALFORMED LINE CHECK
        # --------------------------------------------------

        if len(line.split()) < 3:
            print(
                f"WARNING: Skipping malformed log line "
                f"{line_number}"
            )
            continue

        if not re.match(timestamp_pattern, line):
            print(
                f"WARNING: Skipping malformed log line "
                f"{line_number}"
            )
            continue

        # --------------------------------------------------
        # COUNT ERRORS AND WARNINGS
        # --------------------------------------------------

        if "ERROR" in line:
            total_errors += 1

        if "WARNING" in line:
            total_warnings += 1

        # --------------------------------------------------
        # CPU USAGE
        # --------------------------------------------------

        if "CPU usage reached" in line:

            try:
                cpu_value = int(
                    line.split("CPU usage reached ")[1]
                    .split("%")[0]
                )

                if cpu_value >= CPU_THRESHOLD:

                    report.append(
                        f"[HIGH] [RESOURCE EXHAUSTION] {line}"
                    )

                    high_alerts += 1

            except (ValueError, IndexError):

                print(
                    f"WARNING: Could not parse CPU usage "
                    f"on line {line_number}"
                )

        # --------------------------------------------------
        # DISK USAGE
        # --------------------------------------------------

        if "Disk usage reached" in line:

            try:
                disk_value = int(
                    line.split("Disk usage reached ")[1]
                    .split("%")[0]
                )

                if disk_value >= DISK_THRESHOLD:

                    report.append(
                        f"[HIGH] [RESOURCE EXHAUSTION] {line}"
                    )

                    high_alerts += 1

            except (ValueError, IndexError):

                print(
                    f"WARNING: Could not parse disk usage "
                    f"on line {line_number}"
                )

        # --------------------------------------------------
        # MEMORY USAGE
        # --------------------------------------------------

        if "High memory usage" in line:

            report.append(
                f"[HIGH] [RESOURCE EXHAUSTION] {line}"
            )

            high_alerts += 1

        # --------------------------------------------------
        # FAILED LOGIN
        # --------------------------------------------------

        if "Failed login attempt" in line:

            severity = get_severity(line)
            attack_type = classify_attack(line)

            report.append(
                f"[{severity}] [{attack_type}] {line}"
            )

            failed_login_events += 1

            # Extract username
            try:
                username = (
                    line.split("user '")[1]
                    .split("'")[0]
                )
            except IndexError:
                username = "unknown"

            # Extract IP address
            try:
                ip = line.split("from ")[1].strip()
            except IndexError:
                ip = "unknown"

            # --------------------------------------------------
            # USER FAILED LOGIN TRACKING
            # --------------------------------------------------

            if username not in failed_logins:
                failed_logins[username] = 0

            failed_logins[username] += 1

            # --------------------------------------------------
            # IP FAILED LOGIN TRACKING
            # --------------------------------------------------

            if ip not in ip_failed_logins:
                ip_failed_logins[ip] = 0

            ip_failed_logins[ip] += 1

            # --------------------------------------------------
            # USERS TARGETED BY IP
            # --------------------------------------------------

            if ip not in ip_users:
                ip_users[ip] = set()

            ip_users[ip].add(username)

            # --------------------------------------------------
            # TIMESTAMP TRACKING
            # --------------------------------------------------

            try:

                timestamp_string = " ".join(
                    line.split()[:2]
                )

                timestamp = datetime.strptime(
                    timestamp_string,
                    "%Y-%m-%d %H:%M:%S"
                )

                if username not in user_login_times:
                    user_login_times[username] = []

                user_login_times[username].append(
                    timestamp
                )

                if ip not in ip_login_times:
                    ip_login_times[ip] = []

                ip_login_times[ip].append(
                    timestamp
                )

            except (ValueError, IndexError):

                print(
                    f"WARNING: Could not parse timestamp "
                    f"on line {line_number}"
                )

        # --------------------------------------------------
        # INVALID PASSWORD
        # --------------------------------------------------

        elif "Invalid password" in line:

            severity = get_severity(line)
            attack_type = classify_attack(line)

            report.append(
                f"[{severity}] [{attack_type}] {line}"
            )

            high_alerts += 1
            authentication_failures += 1

        # --------------------------------------------------
        # DATABASE FAILURE
        # --------------------------------------------------

        elif "Database connection failed" in line:

            severity = get_severity(line)
            attack_type = classify_attack(line)

            report.append(
                f"[{severity}] [{attack_type}] {line}"
            )

            medium_alerts += 1

        # --------------------------------------------------
        # AUTHENTICATION FAILURE
        # --------------------------------------------------

        elif "authentication failed" in line.lower():

            severity = get_severity(line)
            attack_type = classify_attack(line)

            report.append(
                f"[{severity}] [{attack_type}] {line}"
            )

            medium_alerts += 1
            authentication_failures += 1

        # --------------------------------------------------
        # GENERAL ERROR
        # --------------------------------------------------

        elif "ERROR" in line:

            report.append(
                f"[MEDIUM] [GENERAL ERROR] {line}"
            )

            medium_alerts += 1

    # IMPORTANT:
    # critical_alerts is calculated later from the
    # different detection functions.
    # We return 0 here so the API receives a
    # consistent 13-value structure.

    critical_alerts = 0

    return (
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
    )


# ==================================================
# BRUTE FORCE DETECTION
# ==================================================

def detect_brute_force(
    report,
    failed_logins,
    ip_failed_logins
):

    critical_alerts = 0
    brute_force_incidents = 0

    # --------------------------------------------------
    # USER
    # --------------------------------------------------

    for username, count in failed_logins.items():

        if count >= FAILED_LOGIN_THRESHOLD:

            report.append(
                f"[CRITICAL] [BRUTE FORCE ATTACK] "
                f"SECURITY ALERT: {username} has "
                f"{count} failed login attempts"
            )

            critical_alerts += 1
            brute_force_incidents += 1

    # --------------------------------------------------
    # IP
    # --------------------------------------------------

    for ip, count in ip_failed_logins.items():

        if count >= FAILED_LOGIN_THRESHOLD:

            report.append(
                f"[CRITICAL] [BRUTE FORCE ATTACK] "
                f"SECURITY ALERT: IP {ip} has "
                f"{count} failed login attempts"
            )

            critical_alerts += 1

    return critical_alerts, brute_force_incidents


# ==================================================
# MULTIPLE USERS FROM SAME IP
# ==================================================

def detect_multiple_users(report, ip_users):

    critical_alerts = 0

    for ip, users in ip_users.items():

        if len(users) > 1:

            users_list = ", ".join(sorted(users))

            report.append(
                f"[CRITICAL] [SUSPICIOUS IP ACTIVITY] "
                f"SECURITY ALERT: IP {ip} targeted "
                f"multiple users: {users_list}"
            )

            critical_alerts += 1

    return critical_alerts


# ==================================================
# RAPID LOGIN DETECTION
# ==================================================

def detect_rapid_logins(user_login_times):

    rapid_report = []
    critical_alerts = 0

    rapid_alerted_users = set()

    for username, timestamps in user_login_times.items():

        if len(timestamps) < 2:
            continue

        timestamps.sort()

        for i in range(1, len(timestamps)):

            difference = (
                timestamps[i] - timestamps[i - 1]
            ).total_seconds()

            if difference <= RAPID_LOGIN_THRESHOLD:

                if username not in rapid_alerted_users:

                    rapid_report.append(
                        f"[CRITICAL] SECURITY ALERT: "
                        f"{username} had rapid failed login "
                        f"attempts within {difference} seconds"
                    )

                    critical_alerts += 1
                    rapid_alerted_users.add(username)

                break

    return rapid_report, critical_alerts


# ==================================================
# LOGIN BURST DETECTION
# ==================================================

def detect_login_bursts(ip_login_times):

    burst_report = []
    critical_alerts = 0

    for ip, timestamps in ip_login_times.items():

        if len(timestamps) < BURST_LOGIN_THRESHOLD:
            continue

        timestamps.sort()

        for i in range(len(timestamps)):

            start_time = timestamps[i]
            count = 0

            for timestamp in timestamps[i:]:

                difference = (
                    timestamp - start_time
                ).total_seconds()

                if difference <= BURST_LOGIN_WINDOW:
                    count += 1
                else:
                    break

            if count >= BURST_LOGIN_THRESHOLD:

                burst_report.append(
                    f"[CRITICAL] SECURITY ALERT: "
                    f"IP {ip} generated {count} failed login "
                    f"attempts within {BURST_LOGIN_WINDOW} seconds"
                )

                critical_alerts += 1
                break

    return burst_report, critical_alerts


# ==================================================
# BUILD FINAL REPORT
# ==================================================

def build_final_report(
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
):

    final_report = []

    final_report.append("--- Security Summary ---")

    final_report.append(
        f"Total Errors: {total_errors}"
    )

    final_report.append(
        f"Total Warnings: {total_warnings}"
    )

    final_report.append(
        f"Critical Alerts: {critical_alerts}"
    )

    final_report.append(
        f"High Alerts: {high_alerts}"
    )

    final_report.append(
        f"Medium Alerts: {medium_alerts}"
    )

    final_report.append(
        f"Failed Login Events: {failed_login_events}"
    )

    final_report.append(
        f"Brute Force Incidents: {brute_force_incidents}"
    )

    final_report.append(
        f"Authentication Failures: {authentication_failures}"
    )

    final_report.append("")

    final_report.extend(report)

    # --------------------------------------------------
    # RAPID LOGIN REPORT
    # --------------------------------------------------

    if rapid_report:

        final_report.append("")

        final_report.append(
            "--- Rapid Login Detection ---"
        )

        final_report.extend(rapid_report)

    # --------------------------------------------------
    # LOGIN BURST REPORT
    # --------------------------------------------------

    if burst_report:

        final_report.append("")

        final_report.append(
            "--- Login Burst Detection ---"
        )

        final_report.extend(burst_report)

    return final_report


# ==================================================
# MAIN FUNCTION
# ==================================================

def main():

    args = parse_arguments()

    log_file = args.log
    output_file = args.output
    json_output_file = args.json_output

    file = open_log_file(log_file)

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
    ) = process_log_file(file)

    file.close()

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
        brute_force_alerts
        + multiple_user_alerts
        + rapid_alerts
        + burst_alerts
    )

    # --------------------------------------------------
    # BUILD REPORT
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
    # SAVE TXT REPORT
    # --------------------------------------------------

    save_report(
        final_report,
        output_file
    )

    # --------------------------------------------------
    # SAVE JSON REPORT
    # --------------------------------------------------

    if json_output_file:

        json_data = {
            "summary": {
                "total_errors": total_errors,
                "total_warnings": total_warnings,
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "medium_alerts": medium_alerts,
                "failed_login_events": failed_login_events,
                "brute_force_incidents": brute_force_incidents,
                "authentication_failures": authentication_failures
            },
            "alerts": report,
            "rapid_login_detection": rapid_report,
            "login_burst_detection": burst_report
        }

        save_json_report(
            json_data,
            json_output_file
        )


# ==================================================
# PROGRAM ENTRY POINT
# ==================================================

if __name__ == "__main__":
    main()