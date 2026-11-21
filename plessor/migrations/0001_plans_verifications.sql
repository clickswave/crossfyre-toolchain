-- A template scan's plan, and the templates it was made from: a digest of each template
-- as it was written and of the version that ran them. A scan taken up again under other
-- templates, or one edited since, plans again.
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

-- Each time a finding's proof was replayed: what it came to, on what evidence, the status
-- and body hash of the answer, and when. A replay of a proof handed in names no finding,
-- only the proof's hash. A finding, kept in the findings table every engine has, is never
-- changed by one.
CREATE TABLE verifications (
    id              BIGSERIAL PRIMARY KEY,
    finding_id      BIGINT REFERENCES findings (id) ON DELETE CASCADE,
    proof_sha256    TEXT NOT NULL,
    answer          TEXT NOT NULL CHECK (answer IN
                        ('reproduced', 'not reproduced', 'unreachable', 'changed')),
    evidence        JSONB NOT NULL DEFAULT '[]',
    status          INTEGER,
    response_sha256 TEXT NOT NULL DEFAULT '',
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
