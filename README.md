# SentinelDesk

A Python log intelligence service that ingests authentication logs and flags
suspicious activity. Built with Flask and PostgreSQL.

## What it detects

| Detector | Signal | Default threshold |
| --- | --- | --- |
| Brute force | Repeated failed logins from a single IP | 5 failures in 10 minutes |
| Credential stuffing | One IP failing against many usernames | 3 distinct usernames in 30 minutes |
| Suspicious login time | Failed logins during quiet hours | 2 failures between 22:00 and 06:00, last 24 hours |

Thresholds live as named constants at the top of `app/detectors.py`.

## Setup

```bash
git clone https://github.com/anthonymedinav8/sentineldesk.git
cd sentineldesk

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

createdb sentineldesk
psql -d sentineldesk -f schema.sql

cp .env.example .env      # then fill in your Postgres user and password
```

## Run

```bash
python -m app.main
```

The service listens on port 5001 by default.

## API

Ingest a log line:

```bash
curl -X POST http://localhost:5001/logs \
  -H "Content-Type: application/json" \
  -d '{
        "timestamp": "2026-08-31T03:14:00Z",
        "username": "admin",
        "ip_address": "203.0.113.42",
        "status": "failure",
        "raw_log": "sshd: Failed password for admin from 203.0.113.42"
      }'
```

Read current alerts:

```bash
curl http://localhost:5001/alerts
```

```json
{
  "count": 1,
  "alerts": [
    {
      "type": "brute_force",
      "ip_address": "203.0.113.42",
      "attempt_count": 6,
      "message": "Brute force detected from 203.0.113.42: 6 failed attempts in 10 minutes"
    }
  ]
}
```

## Design notes

- All SQL is parameterized. No user input is ever concatenated into a query.
- Credentials are read from the environment. Nothing sensitive is committed.
- Every detection window is bounded, so alert volume does not grow without limit.
- Database connections are closed in a `finally` block so a failed query cannot leak them.
- Debug mode is off unless `FLASK_DEBUG=1` is set explicitly, because the
  Werkzeug debugger permits remote code execution when exposed.

## Roadmap

- Automated tests for each detector
- Deployment to AWS with Terraform