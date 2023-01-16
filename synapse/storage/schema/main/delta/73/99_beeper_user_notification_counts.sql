CREATE TABLE beeper_user_notification_counts (
  user_id               TEXT,
  room_id               TEXT,
  thread_id             TEXT,
  event_stream_ordering BIGINT,
  notifs                BIGINT,
  unreads               BIGINT,
  highlights            BIGINT,
  aggregated            BOOLEAN,
  UNIQUE (user_id, room_id, thread_id, event_stream_ordering)
);

CREATE TABLE beeper_user_notification_counts_stream_ordering (
  lock CHAR(1) NOT NULL DEFAULT 'X' UNIQUE,  -- Makes sure this table only has one row.
  event_stream_ordering BIGINT NOT NULL,
  CHECK (lock='X')
);

INSERT INTO beeper_user_notification_counts_stream_ordering (event_stream_ordering) VALUES (0);
