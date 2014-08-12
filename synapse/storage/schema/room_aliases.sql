CREATE TABLE IF NOT EXISTS room_aliases(
    room_alias TEXT NOT NULL,
    room_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS room_alias_servers(
    room_alias TEXT NOT NULL,
    server TEXT NOT NULL
);



