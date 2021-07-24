

DELETE FROM event_to_state_groups WHERE state_group not in (
    SELECT MAX(state_group) FROM event_to_state_groups GROUP BY event_id
);

DELETE FROM event_to_state_groups WHERE rowid not in (
    SELECT MIN(rowid) FROM event_to_state_groups GROUP BY event_id
);
