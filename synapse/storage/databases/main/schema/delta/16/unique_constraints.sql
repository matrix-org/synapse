
-- We can use SQLite features here, since other db support was only added in v16

--
DELETE FROM current_state_events WHERE rowid not in (
    SELECT MIN(rowid) FROM current_state_events GROUP BY event_id
);

DROP INDEX IF EXISTS current_state_events_event_id;
CREATE UNIQUE INDEX current_state_events_event_id ON current_state_events(event_id);

--
DELETE FROM room_memberships WHERE rowid not in (
    SELECT MIN(rowid) FROM room_memberships GROUP BY event_id
);

DROP INDEX IF EXISTS room_memberships_event_id;
CREATE UNIQUE INDEX room_memberships_event_id ON room_memberships(event_id);

--
DELETE FROM topics WHERE rowid not in (
    SELECT MIN(rowid) FROM topics GROUP BY event_id
);

DROP INDEX IF EXISTS topics_event_id;
CREATE UNIQUE INDEX topics_event_id ON topics(event_id);

--
DELETE FROM room_names WHERE rowid not in (
    SELECT MIN(rowid) FROM room_names GROUP BY event_id
);

DROP INDEX IF EXISTS room_names_id;
CREATE UNIQUE INDEX room_names_id ON room_names(event_id);

--
DELETE FROM presence WHERE rowid not in (
    SELECT MIN(rowid) FROM presence GROUP BY user_id
);

DROP INDEX IF EXISTS presence_id;
CREATE UNIQUE INDEX presence_id ON presence(user_id);

--
DELETE FROM presence_allow_inbound WHERE rowid not in (
    SELECT MIN(rowid) FROM presence_allow_inbound
    GROUP BY observed_user_id, observer_user_id
);

DROP INDEX IF EXISTS presence_allow_inbound_observers;
CREATE UNIQUE INDEX presence_allow_inbound_observers ON presence_allow_inbound(
    observed_user_id, observer_user_id
);

--
DELETE FROM presence_list WHERE rowid not in (
    SELECT MIN(rowid) FROM presence_list
    GROUP BY user_id, observed_user_id
);

DROP INDEX IF EXISTS presence_list_observers;
CREATE UNIQUE INDEX presence_list_observers ON presence_list(
    user_id, observed_user_id
);

--
DELETE FROM room_aliases WHERE rowid not in (
    SELECT MIN(rowid) FROM room_aliases GROUP BY room_alias
);

DROP INDEX IF EXISTS room_aliases_id;
CREATE INDEX room_aliases_id ON room_aliases(room_id);
