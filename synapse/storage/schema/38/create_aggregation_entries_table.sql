CREATE TABLE IF NOT EXISTS aggregation_entries(
    target_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    event_name TEXT NOT NULL,
    latest_event_id TEXT NOT NULL,
    aggregation_data JSONB NOT NULL DEFAULT jsonb('[]')
);

CREATE UNIQUE INDEX aggregation_entries_target_id_event_name ON aggregation_entries(target_id, event_name);
