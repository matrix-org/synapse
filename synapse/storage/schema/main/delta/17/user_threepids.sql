CREATE TABLE user_threepids (
    user_id TEXT NOT NULL,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    validated_at BIGINT NOT NULL,
    added_at BIGINT NOT NULL,
    CONSTRAINT user_medium_address UNIQUE (user_id, medium, address)
);
CREATE INDEX user_threepids_user_id ON user_threepids(user_id);
