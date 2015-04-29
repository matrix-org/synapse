CREATE TABLE user_threepids (
    id INTEGER PRIMARY KEY NOT NULL,
    user TEXT NOT NULL,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    validated_at INTEGER NOT NULL,
    added_at INTEGER NOT NULL,
    CONSTRAINT user_medium_address UNIQUE (user, medium, address) ON CONFLICT REPLACE
);
CREATE INDEX user_threepids_user ON user_threepids(user);
