CREATE TABLE background_updates (
    update_name text NOT NULL,
    progress_json text NOT NULL,
    depends_on text,
    ordering integer DEFAULT 0 NOT NULL
);
ALTER TABLE ONLY background_updates
    ADD CONSTRAINT background_updates_uniqueness UNIQUE (update_name);
