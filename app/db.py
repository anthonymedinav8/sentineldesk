import os

import psycopg2


def get_db():
    """Open a connection to the SentinelDesk database.

    Credentials come from the environment so nothing sensitive is committed.
    """
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME", "sentineldesk"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST", "localhost"),
    )


def fetch_all(sql, params=()):
    """Run a read query and return every row, always closing the connection."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()


def execute(sql, params=()):
    """Run a write query and commit, rolling back if it fails."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    