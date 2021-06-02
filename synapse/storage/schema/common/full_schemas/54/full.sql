

CREATE TABLE background_updates (
    update_name text NOT NULL,
    progress_json text NOT NULL,
    depends_on text,
    CONSTRAINT background_updates_uniqueness UNIQUE (update_name)
);
