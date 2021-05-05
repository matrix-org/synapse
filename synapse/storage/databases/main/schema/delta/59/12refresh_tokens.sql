CREATE TABLE refresh_tokens (
    id BIGINT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT,
    token TEXT NOT NULL,
    next_token_id BIGINT REFERENCES refresh_tokens (id) ON DELETE CASCADE,
    UNIQUE(token)
);

ALTER TABLE "access_tokens"
    ADD COLUMN refresh_token_id BIGINT REFERENCES refresh_tokens (id) ON DELETE CASCADE;
