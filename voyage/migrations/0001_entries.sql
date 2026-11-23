-- The names a scan tries, and what was found about each.
CREATE TABLE scan_entries (
    id             BIGSERIAL PRIMARY KEY,
    scan_id        TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    full_subdomain TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued',
    method         TEXT NOT NULL DEFAULT 'active',
    source         TEXT NOT NULL DEFAULT '',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, full_subdomain)
);
CREATE INDEX scan_entries_scan_status ON scan_entries (scan_id, status);

-- What one-off probes found, kept for as long as the request asked.
CREATE TABLE probe_results (
    id           BIGSERIAL PRIMARY KEY,
    operation_id TEXT NOT NULL,
    domain       TEXT NOT NULL,
    found        BOOLEAN NOT NULL DEFAULT false,
    technique    TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delete_after TIMESTAMPTZ NOT NULL
);
CREATE INDEX probe_results_delete_after ON probe_results (delete_after);
