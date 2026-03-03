from contextlib import contextmanager

import psycopg

from app.config import Settings


SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS kb_examples (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('alert', 'incident')),
    alert_id TEXT NULL,
    incident_id TEXT NULL,
    fingerprint TEXT NULL,
    provider_id TEXT NULL,
    source JSONB NOT NULL DEFAULT '[]'::jsonb,
    current_severity TEXT NULL,
    proposed_severity TEXT NOT NULL CHECK (proposed_severity IN ('info','warning','high','critical')),
    reason TEXT NOT NULL,
    alert_text TEXT NOT NULL,
    incident_alerts JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    dedupe_hash TEXT NOT NULL,
    embedding VECTOR(768) NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_kb_examples_tenant_dedupe_active
    ON kb_examples (tenant_id, dedupe_hash)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_kb_examples_tenant_scope
    ON kb_examples (tenant_id, scope)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_kb_examples_tenant_proposed
    ON kb_examples (tenant_id, proposed_severity)
    WHERE deleted_at IS NULL;
"""


@contextmanager
def get_conn(settings: Settings):
    conn = psycopg.connect(settings.db_dsn)
    try:
        yield conn
    finally:
        conn.close()


def init_schema(settings: Settings):
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
            # HNSW can fail on older pgvector versions; service still works with seq scan.
            try:
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS ix_kb_examples_embedding_hnsw
                    ON kb_examples USING hnsw (embedding vector_cosine_ops);
                    """
                )
            except Exception:
                conn.rollback()
                with conn.cursor() as rollback_cur:
                    rollback_cur.execute(SCHEMA_SQL)
            conn.commit()
