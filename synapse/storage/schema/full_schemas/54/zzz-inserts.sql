INSERT INTO user_directory_stream_pos (stream_id) VALUES (null);

INSERT INTO appservice_stream_position (stream_ordering) VALUES (0);

INSERT INTO device_max_stream_id (stream_id) VALUES (0);

INSERT INTO event_push_summary_stream_ordering (stream_ordering) VALUES (0);

INSERT INTO federation_stream_position (type, stream_id) VALUES ('federation', -1);
INSERT INTO federation_stream_position (type, stream_id) VALUES ('events', -1);
