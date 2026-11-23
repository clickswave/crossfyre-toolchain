-- Word lists, each kept once and known by the SHA-512 of its words.
CREATE TABLE wordlists (
    id   BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    hash TEXT UNIQUE
);
CREATE TABLE words (
    id          BIGSERIAL PRIMARY KEY,
    word        TEXT NOT NULL,
    wordlist_id BIGINT NOT NULL REFERENCES wordlists (id) ON DELETE CASCADE
);
CREATE INDEX words_wordlist_id ON words (wordlist_id, id);

-- The URLs a scan requests, with the marker each word goes in at.
CREATE TABLE urls (
    id      BIGSERIAL PRIMARY KEY,
    url     TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE
);
CREATE INDEX urls_scan_id ON urls (scan_id);

-- One request of a scan, a URL with a word in it, and what it got back: its status, its
-- code and its lengths. The response itself is not kept.
CREATE TABLE scan_entries (
    id             BIGSERIAL PRIMARY KEY,
    scan_id        TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    url_id         BIGINT NOT NULL REFERENCES urls (id) ON DELETE CASCADE,
    word_id        BIGINT NOT NULL REFERENCES words (id),
    status         TEXT NOT NULL DEFAULT 'queued',
    request_status INTEGER NOT NULL DEFAULT 0,
    headers_length BIGINT NOT NULL DEFAULT 0,
    body_length    BIGINT NOT NULL DEFAULT 0
);
-- Every hot query filters by (scan_id, status): the claim, the results, the counts.
CREATE INDEX scan_entries_scan_status ON scan_entries (scan_id, status);

-- What one-off probes found, kept for as long as the request asked.
CREATE TABLE probe_results (
    id             BIGSERIAL PRIMARY KEY,
    operation_id   TEXT NOT NULL,
    url            TEXT NOT NULL,
    status         TEXT NOT NULL,
    code           INTEGER NOT NULL DEFAULT 0,
    body_length    BIGINT NOT NULL DEFAULT 0,
    headers_length BIGINT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    delete_after   TIMESTAMPTZ NOT NULL
);
CREATE INDEX probe_results_delete_after ON probe_results (delete_after);
