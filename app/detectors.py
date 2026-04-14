from datetime import datetime, timedelta
import psycopg2
import os

def get_db():
    return psycopg2.connect(
        dbname="sentineldesk",
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host="localhost"
    )

def detect_brute_force():
    conn = get_db()
    cur = conn.cursor()

    window = datetime.utcnow() - timedelta(minutes=10)

    cur.execute("""
        SELECT ip_address, COUNT(*) as attempt_count
        FROM auth_logs
        WHERE status = 'failure'
        AND timestamp >= %s
        GROUP BY ip_address
        HAVING COUNT(*) >= 5
    """, (window,))

    results = cur.fetchall()
    cur.close()
    conn.close()

    alerts = []
    for row in results:
        alerts.append({
            "type": "brute_force",
            "ip_address": row[0],
            "attempt_count": row[1],
            "message": f"Brute force detected from {row[0]}: {row[1]} failed attempts in 10 minutes"
        })

    return alerts
def detect_credential_stuffing():
    conn = get_db()
    cur = conn.cursor()

    window = datetime.utcnow() - timedelta(minutes=10)

    cur.execute("""
        SELECT ip_address, COUNT(DISTINCT username) as username_count
        FROM auth_logs
        WHERE status = 'failure'
        AND timestamp >= %s
        GROUP BY ip_address
        HAVING COUNT(DISTINCT username) >= 5
    """, (window,))

    results = cur.fetchall()
    cur.close()
    conn.close()

    alerts = []
    for row in results:
        alerts.append({
            "type": "credential_stuffing",
            "ip_address": row[0],
            "username_count": row[1],
            "message": f"Credential stuffing detected from {row[0]}: {row[1]} unique usernames tried in 10 minutes"
        })

    return alerts
def detect_suspicious_login_times():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT ip_address, username, timestamp
        FROM auth_logs
        WHERE EXTRACT(HOUR FROM timestamp) < 6
        OR EXTRACT(HOUR FROM timestamp) > 22
    """)

    results = cur.fetchall()
    cur.close()
    conn.close()

    alerts = []
    for row in results:
        alerts.append({
            "type": "suspicious_login_time",
            "ip_address": row[0],
            "username": row[1],
            "timestamp": str(row[2]),
            "message": f"Suspicious login from {row[0]}: {row[1]} at {row[2]}"
        })

    return alerts
