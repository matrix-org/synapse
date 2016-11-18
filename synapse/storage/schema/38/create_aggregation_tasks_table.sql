CREATE TABLE IF NOT EXISTS aggregation_tasks(
    room_id TEXT NOT NULL,
    aggregation_event_name TEXT NOT NULL,
    aggregation_spec JSONB NOT NULL
);

CREATE INDEX aggregation_tasks_room_id ON aggregation_tasks(room_id);
