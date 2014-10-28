
CREATE TABLE IF NOT EXISTS event_forward_extremities(
    event_id TEXT,
    room_id TEXT,
    CONSTRAINT uniqueness UNIQUE (event_id, room_id) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS ev_extrem_room ON event_forward_extremities(room_id);
CREATE INDEX IF NOT EXISTS ev_extrem_id ON event_forward_extremities(event_id);
--

CREATE TABLE IF NOT EXISTS event_backward_extremities(
    event_id TEXT,
    room_id TEXT,
    CONSTRAINT uniqueness UNIQUE (event_id, room_id) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS ev_b_extrem_room ON event_backward_extremities(room_id);
CREATE INDEX IF NOT EXISTS ev_b_extrem_id ON event_backward_extremities(event_id);
--

CREATE TABLE IF NOT EXISTS event_edges(
    event_id TEXT,
    prev_event_id TEXT,
    room_id TEXT,
    CONSTRAINT uniqueness UNIQUE (event_id, prev_event_id, room_id)
);

CREATE INDEX IF NOT EXISTS ev_edges_id ON event_edges(event_id);
CREATE INDEX IF NOT EXISTS ev_edges_prev_id ON event_edges(prev_event_id);
--


CREATE TABLE IF NOT EXISTS room_depth(
    room_id TEXT,
    min_depth INTEGER,
    CONSTRAINT uniqueness UNIQUE (room_id)
);

CREATE INDEX IF NOT EXISTS room_depth_room ON room_depth(room_id);
--

create TABLE IF NOT EXISTS event_destinations(
    event_id TEXT,
    destination TEXT,
    delivered_ts INTEGER DEFAULT 0, -- or 0 if not delivered
    CONSTRAINT uniqueness UNIQUE (event_id, destination) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS event_destinations_id ON event_destinations(event_id);
--