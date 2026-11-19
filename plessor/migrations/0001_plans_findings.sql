-- A template scan's plan, and the templates it was made from: a digest of their ids and
-- the version that ran them. A scan taken up again under other templates plans again.
CREATE TABLE plans (
    scan_id TEXT PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    pack    TEXT NOT NULL
);

-- Where each template of a scan is: queued, sent, matched (waiting on an out-of-band
-- callback), confirmed, held back (it changes the target), or skipped with the reason.
-- A scan taken up again runs what is queued, and what was matched, as its callback can
-- no longer come.
CREATE TABLE template_states (
    scan_id     TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    template_id TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN
                    ('queued', 'sent', 'matched', 'confirmed', 'held_back', 'skipped')),
    reason      TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_id, template_id)
);

-- What a scan found, kept with no credential in it, and each once: a scan taken up again
-- reports what it had found, and finds again what it checks again.
CREATE TABLE findings (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    template_id TEXT,
    data        JSONB NOT NULL,
    digest      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, digest)
);
