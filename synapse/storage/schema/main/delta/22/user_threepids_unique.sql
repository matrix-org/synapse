CREATE TABLE IF NOT EXISTS user_threepids2 (
    user_id TEXT NOT NULL,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    validated_at BIGINT NOT NULL,
    added_at BIGINT NOT NULL,
    CONSTRAINT medium_address UNIQUE (medium, address)
);

INSERT INTO user_threepids2
	SELECT * FROM user_threepids WHERE added_at IN (
		SELECT max(added_at) FROM user_threepids GROUP BY medium, address
	)
;

DROP TABLE user_threepids;
ALTER TABLE user_threepids2 RENAME TO user_threepids;

CREATE INDEX user_threepids_user_id ON user_threepids(user_id);
