from datetime import datetime, timedelta, timezone

from app.db import fetch_all

BRUTE_FORCE_WINDOW_MINUTES = 10
BRUTE_FORCE_THRESHOLD = 5

CREDENTIAL_STUFFING_WINDOW_MINUTES = 30
CREDENTIAL_STUFFING_THRESHOLD = 3

SUSPICIOUS_TIME_WINDOW_HOURS = 24
SUSPICIOUS_TIME_THRESHOLD = 2
QUIET_HOURS_START = 22
QUIET_HOURS_END = 6


def _window(**kwargs):
    """Return the timezone aware cutoff for a detection window."""
    return datetime.now(timezone.utc) - timedelta(**kwargs)


def detect_brute_force():
    """Many failed logins from one IP in a short window."""
    rows = fetch_all(
        """
        SELECT ip_address, COUNT(*) AS attempt_count
        FROM auth_logs
        WHERE status = 'failure'
          AND timestamp >= %s
        GROUP BY ip_address
        HAVING COUNT(*) >= %s
        """,
        (_window(minutes=BRUTE_FORCE_WINDOW_MINUTES), BRUTE_FORCE_THRESHOLD),
    )

    return [
        {
            "type": "brute_force",
            "ip_address": ip,
            "attempt_count": count,
            "message": (
                f"Brute force detected from {ip}: {count} failed attempts "
                f"in {BRUTE_FORCE_WINDOW_MINUTES} minutes"
            ),
        }
        for ip, count in rows
    ]


def detect_credential_stuffing():
    """One IP failing against many different usernames."""
    rows = fetch_all(
        """
        SELECT ip_address, COUNT(DISTINCT username) AS username_count
        FROM auth_logs
        WHERE status = 'failure'
          AND timestamp >= %s
        GROUP BY ip_address
        HAVING COUNT(DISTINCT username) >= %s
        """,
        (
            _window(minutes=CREDENTIAL_STUFFING_WINDOW_MINUTES),
            CREDENTIAL_STUFFING_THRESHOLD,
        ),
    )

    return [
        {
            "type": "credential_stuffing",
            "ip_address": ip,
            "username_count": count,
            "message": (
                f"Credential stuffing detected from {ip}: {count} unique "
                f"usernames tried in {CREDENTIAL_STUFFING_WINDOW_MINUTES} minutes"
            ),
        }
        for ip, count in rows
    ]


def detect_suspicious_login_times():
    """Repeated failures during quiet hours, bounded to a recent window."""
    rows = fetch_all(
        """
        SELECT ip_address, COUNT(*) AS attempt_count
        FROM auth_logs
        WHERE status = 'failure'
          AND timestamp >= %s
          AND (EXTRACT(HOUR FROM timestamp) < %s
               OR EXTRACT(HOUR FROM timestamp) > %s)
        GROUP BY ip_address
        HAVING COUNT(*) >= %s
        """,
        (
            _window(hours=SUSPICIOUS_TIME_WINDOW_HOURS),
            QUIET_HOURS_END,
            QUIET_HOURS_START,
            SUSPICIOUS_TIME_THRESHOLD,
        ),
    )

    return [
        {
            "type": "suspicious_login_time",
            "ip_address": ip,
            "attempt_count": count,
            "message": (
                f"Suspicious login from {ip}: {count} failed attempts "
                f"outside {QUIET_HOURS_END}:00 to {QUIET_HOURS_START}:00"
            ),
        }
        for ip, count in rows
    ]


def run_all_detectors():
    """Run every detector and return one combined list of alerts."""
    return (
        detect_brute_force()
        + detect_credential_stuffing()
        + detect_suspicious_login_times()
    )
