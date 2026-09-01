-- SentinelDesk database schema
-- Create the database first:  createdb sentineldesk
-- Then load this file:        psql -d sentineldesk -f schema.sql

CREATE TABLE IF NOT EXISTS auth_logs (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    username    TEXT        NOT NULL,
    ip_address  INET        NOT NULL,
    status      TEXT        NOT NULL CHECK (status IN ('success', 'failure')),
    raw_log     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The detectors filter on status and timestamp and group by ip_address,
-- so this index covers every query in detectors.py.
CREATE INDEX IF NOT EXISTS idx_auth_logs_status_timestamp
    ON auth_logs (status, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_auth_logs_ip_address
    ON auth_logs (ip_address);
