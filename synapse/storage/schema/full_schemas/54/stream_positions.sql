
INSERT INTO appservice_stream_position (stream_ordering) SELECT COALESCE(MAX(stream_ordering), 0) FROM events;
INSERT INTO federation_stream_position (type, stream_id) VALUES ('federation', -1);
INSERT INTO federation_stream_position (type, stream_id) SELECT 'events', coalesce(max(stream_ordering), -1) FROM events;
INSERT INTO user_directory_stream_pos (stream_id) VALUES (null);
INSERT INTO stats_stream_pos (stream_id) VALUES (null);
INSERT INTO event_push_summary_stream_ordering (stream_ordering) VALUES (0);

--- User dir population

-- Set up staging tables
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('populate_user_directory_createtables', '{}');

-- Run through each room and update the user directory according to who is in it
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_user_directory_process_rooms', '{}', 'populate_user_directory_createtables');

-- Insert all users, if search_all_users is on
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_user_directory_process_users', '{}', 'populate_user_directory_process_rooms');

-- Clean up staging tables
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_user_directory_cleanup', '{}', 'populate_user_directory_process_users');

--- Stats population

-- Set up staging tables
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('populate_stats_createtables', '{}');

-- Run through each room and update stats
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_process_rooms', '{}', 'populate_stats_createtables');

-- Clean up staging tables
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_cleanup', '{}', 'populate_stats_process_rooms');
