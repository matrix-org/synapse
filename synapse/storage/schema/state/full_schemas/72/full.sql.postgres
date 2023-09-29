CREATE TABLE state_group_edges (
    state_group bigint NOT NULL,
    prev_state_group bigint NOT NULL
);
CREATE SEQUENCE state_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE state_groups (
    id bigint NOT NULL,
    room_id text NOT NULL,
    event_id text NOT NULL
);
CREATE TABLE state_groups_state (
    state_group bigint NOT NULL,
    room_id text NOT NULL,
    type text NOT NULL,
    state_key text NOT NULL,
    event_id text NOT NULL
);
ALTER TABLE ONLY state_groups_state ALTER COLUMN state_group SET (n_distinct=-0.02);
ALTER TABLE ONLY state_groups
    ADD CONSTRAINT state_groups_pkey PRIMARY KEY (id);
CREATE INDEX state_group_edges_prev_idx ON state_group_edges USING btree (prev_state_group);
CREATE UNIQUE INDEX state_group_edges_unique_idx ON state_group_edges USING btree (state_group, prev_state_group);
CREATE INDEX state_groups_room_id_idx ON state_groups USING btree (room_id);
CREATE INDEX state_groups_state_type_idx ON state_groups_state USING btree (state_group, type, state_key);
SELECT pg_catalog.setval('state_group_id_seq', 1, false);
