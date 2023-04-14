ALTER TABLE device_lists_stream ADD COLUMN instance_name TEXT;

ALTER TABLE user_signature_stream ADD COLUMN instance_name TEXT;
ALTER TABLE device_lists_outbound_pokes ADD COLUMN instance_name TEXT;
ALTER TABLE device_lists_changes_in_room ADD COLUMN instance_name TEXT;
ALTER TABLE device_lists_remote_pending ADD COLUMN instance_name TEXT;
ALTER TABLE device_lists_changes_converted_stream_position ADD COLUMN instance_name TEXT;

ALTER TABLE e2e_cross_signing_keys ADD COLUMN instance_name TEXT;

ALTER TABLE pushers ADD COLUMN instance_name TEXT;
ALTER TABLE deleted_pushers ADD COLUMN instance_name TEXT;
