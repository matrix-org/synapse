
CREATE INDEX IF NOT EXISTS room_aliases_id ON room_aliases(room_id);
CREATE INDEX IF NOT EXISTS room_alias_servers_alias ON room_alias_servers(room_alias);
