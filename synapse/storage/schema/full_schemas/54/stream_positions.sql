
INSERT INTO appservice_stream_position (stream_ordering) SELECT COALESCE(MAX(stream_ordering), 0) FROM events;
INSERT INTO federation_stream_position (type, stream_id) VALUES ('federation', -1);
INSERT INTO federation_stream_position (type, stream_id) SELECT 'events', coalesce(max(stream_ordering), -1) FROM events;
INSERT INTO user_directory_stream_pos (stream_id) VALUES (0);
INSERT INTO stats_stream_pos (stream_id) VALUES (0);
INSERT INTO event_push_summary_stream_ordering (stream_ordering) VALUES (0);
