-- The tables every engine has, the same in each engine's schema, so the dashboard and
-- the `db` commands read them alike.

-- A scan: what it was pointed at, what it was asked to do, and where it is. A scan
-- with the same config_hash as a stopped one resumes that one. A scan that
-- authenticates to its target has none, and is resumed by its id.
CREATE TABLE scans (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    target      TEXT NOT NULL,
    config_hash TEXT,
    params      JSONB NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'stopped', 'completed', 'failed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scans_config_hash ON scans (config_hash, status);
CREATE INDEX scans_created_at ON scans (created_at);

-- What a scan said as it ran.
CREATE TABLE logs (
    id         BIGSERIAL PRIMARY KEY,
    scan_id    TEXT REFERENCES scans (id) ON DELETE CASCADE,
    level      TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX logs_scan_id ON logs (scan_id);

-- The requests the daemon was sent and asked to keep, and how each ended.
CREATE TABLE operations (
    id         TEXT PRIMARY KEY,
    operation  TEXT NOT NULL,
    scan_id    TEXT REFERENCES scans (id) ON DELETE CASCADE,
    params     JSONB NOT NULL DEFAULT '{}',
    status     TEXT NOT NULL DEFAULT 'queued'
               CHECK (status IN ('queued', 'running', 'stopped', 'completed', 'failed')),
    result     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX operations_scan_id ON operations (scan_id);
