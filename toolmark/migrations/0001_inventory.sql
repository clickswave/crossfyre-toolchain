-- A host and port toolmark looked at.
CREATE TABLE hosts (
    id         BIGSERIAL PRIMARY KEY,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    scheme     TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host, port)
);

-- What a scan saw on a host: the landing page's status, its headers in order as
-- [name, value] with no credential's value, and its body, capped as toolmark caps what it
-- reads and gzipped, so that new signatures can be matched against what was seen. A scan
-- with credentials saw the page as the user they belong to, and keeps no body.
CREATE TABLE observations (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    host_id     BIGINT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    status      INTEGER NOT NULL,
    headers     JSONB NOT NULL DEFAULT '[]',
    body        BYTEA,
    body_length BIGINT NOT NULL DEFAULT 0,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX observations_host_id ON observations (host_id, observed_at);

-- A product found on a host, and the evidence and signature that found it.
CREATE TABLE fingerprints (
    id           BIGSERIAL PRIMARY KEY,
    host_id      BIGINT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    product      TEXT NOT NULL,
    vendor       TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL DEFAULT '',
    cpe          TEXT NOT NULL DEFAULT '',
    confidence   INTEGER NOT NULL DEFAULT 0,
    evidence     JSONB NOT NULL DEFAULT '[]',
    signature_id TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, product)
);

-- A service listening on a host's port, and whether it lets anyone in.
CREATE TABLE services (
    id         BIGSERIAL PRIMARY KEY,
    host_id    BIGINT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    service    TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    banner     TEXT NOT NULL DEFAULT '',
    access     TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, service)
);

-- A product that appeared on a host, or whose version changed there.
CREATE TABLE changes (
    id          BIGSERIAL PRIMARY KEY,
    host_id     BIGINT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    product     TEXT NOT NULL,
    old_version TEXT,
    new_version TEXT NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- What toolmark knows runs where: the one way other engines read toolmark's data.
CREATE VIEW inventory AS
    SELECT h.host, h.port, f.vendor, f.product, f.version, f.cpe, f.last_seen
    FROM fingerprints f JOIN hosts h ON h.id = f.host_id;
