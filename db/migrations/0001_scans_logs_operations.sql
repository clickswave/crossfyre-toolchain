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
    -- How far it has got, as it last said, about once a second.
    progress    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scans_config_hash ON scans (config_hash, status);
CREATE INDEX scans_created_at ON scans (created_at);

-- What a scan found, kept with no credential in it, and each once: its digest is of what
-- is kept, without the finding's proof, so the same finding with another proof, or at a
-- URL whose token was rotated, is one. `kind` is what it is (a vulnerability, a
-- technology, an open port), `check_id` the check that found it, where there is one.
CREATE TABLE findings (
    id         BIGSERIAL PRIMARY KEY,
    scan_id    TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT '',
    check_id   TEXT,
    data       JSONB NOT NULL,
    digest     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, digest)
);
CREATE INDEX findings_scan_id ON findings (scan_id, id);

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
