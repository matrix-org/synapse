INSERT INTO device_max_stream_id (stream_id)
SELECT 0
WHERE NOT EXISTS (
    SELECT 1 FROM device_max_stream_id
);