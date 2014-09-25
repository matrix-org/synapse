CREATE TABLE IF NOT EXISTS redactions (
    event_id TEXT NOT NULL,
    redacts TEXT NOT NULL,
    CONSTRAINT ev_uniq UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS redactions_event_id ON redactions (event_id);
CREATE INDEX IF NOT EXISTS redactions_redacts ON redactions (redacts);

ALTER TABLE room_ops_levels ADD COLUMN redact_level INTEGER;

PRAGMA user_version = 4;
