CREATE TABLE user_threepids (
    user TEXT NOT NULL,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    validated_at BIGINT NOT NULL,
    added_at BIGINT NOT NULL,
    CONSTRAINT user_medium_address UNIQUE (user, medium, address)
);
CREATE INDEX user_threepids_user ON user_threepids(user);
