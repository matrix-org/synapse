CREATE INDEX events_order ON events (topological_ordering, stream_ordering);
CREATE INDEX events_order_room ON events (
    room_id, topological_ordering, stream_ordering
);
