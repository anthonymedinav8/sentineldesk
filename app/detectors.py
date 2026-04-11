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