CREATE TABLE IF NOT EXISTS deletions (
    event_id TEXT NOT NULL,
    deletes TEXT NOT NULL,
    CONSTRAINT ev_uniq UNIQUE (event_id)
);
