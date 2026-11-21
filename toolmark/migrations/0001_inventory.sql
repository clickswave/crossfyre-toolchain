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

-- What a scan saw on a host: each page it fetched, the landing page, the two random paths
-- that learn its not-found page, any path a signature asked for and, at the rendered
-- tier, the landing page as a browser built it, with what it was
-- asked for, its status, its headers in order as [name, value] with no credential's
-- value, its body, capped as toolmark caps what it reads and gzipped, and for a landing
-- page that came over TLS the certificate its server presented, DER encoded, so that new
-- signatures can be matched against what was seen. A scan with credentials saw the pages
-- as the user they belong to, and keeps no body.
CREATE TABLE observations (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    host_id     BIGINT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    asked       TEXT NOT NULL CHECK (asked IN ('landing', 'not_found', 'path', 'rendered')),
    url         TEXT NOT NULL,
    status      INTEGER NOT NULL,
    moved       BOOLEAN NOT NULL,
    headers     JSONB NOT NULL DEFAULT '[]',
    body        BYTEA,
    body_length BIGINT NOT NULL DEFAULT 0,
    certificate BYTEA,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX observations_host_id ON observations (host_id, observed_at);

-- A product found on a host, the products it may be by their CPEs (part:vendor:product),
-- the tag of the distribution that built it when one was read, and the evidence and
-- signature that found it.
CREATE TABLE fingerprints (
    id           BIGSERIAL PRIMARY KEY,
    host_id      BIGINT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    product      TEXT NOT NULL,
    vendor       TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL DEFAULT '',
    cpe          TEXT NOT NULL DEFAULT '',
    cpe_names    JSONB NOT NULL DEFAULT '[]',
    distro       TEXT NOT NULL DEFAULT '',
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

-- A CVE lead reported for a product on a host, so a re-match reports only new ones.
CREATE TABLE leads (
    id         BIGSERIAL PRIMARY KEY,
    host_id    BIGINT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    product    TEXT NOT NULL,
    cve        TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, product, cve)
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
    SELECT h.host, h.port, f.vendor, f.product, f.version, f.cpe, f.cpe_names, f.distro,
        f.last_seen
    FROM fingerprints f JOIN hosts h ON h.id = f.host_id;
