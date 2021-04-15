-- Ensure that only one position can be tracked for each stream type.  This might
-- be violated if, for exapmle, a backup is restored without first clearing the
-- table's contents.
CREATE INDEX federation_stream_position_idx ON federation_stream_position(type);
