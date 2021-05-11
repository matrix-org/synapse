
CREATE TABLE open_id_tokens (
    token TEXT NOT NULL PRIMARY KEY,
    ts_valid_until_ms bigint NOT NULL,
    user_id TEXT NOT NULL,
    UNIQUE (token)
);

CREATE index open_id_tokens_ts_valid_until_ms ON open_id_tokens(ts_valid_until_ms);
