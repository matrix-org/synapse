CREATE TABLE IF NOT EXISTS deletions (
    event_id TEXT NOT NULL,
    deletes TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS deletions_event_id ON deletions (event_id);
CREATE INDEX IF NOT EXISTS deletions_deletes ON deletions (deletes);

ALTER TABLE room_ops_levels ADD COLUMN delete_level INTEGER;

PRAGMA user_version = 4;
