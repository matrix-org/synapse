CREATE FUNCTION check_partial_state_events() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM events
                    WHERE events.event_id = NEW.event_id
                       AND events.room_id != NEW.room_id
                ) THEN
                    RAISE EXCEPTION 'Incorrect room_id in partial_state_events';
                END IF;
                RETURN NEW;
            END;
            $$;
CREATE TABLE access_tokens (
    id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text,
    token text NOT NULL,
    valid_until_ms bigint,
    puppets_user_id text,
    last_validated bigint,
    refresh_token_id bigint,
    used boolean
);
CREATE TABLE account_data (
    user_id text NOT NULL,
    account_data_type text NOT NULL,
    stream_id bigint NOT NULL,
    content text NOT NULL,
    instance_name text
);
CREATE SEQUENCE account_data_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE account_validity (
    user_id text NOT NULL,
    expiration_ts_ms bigint NOT NULL,
    email_sent boolean NOT NULL,
    renewal_token text,
    token_used_ts_ms bigint
);
CREATE TABLE application_services_state (
    as_id text NOT NULL,
    state character varying(5),
    read_receipt_stream_id bigint,
    presence_stream_id bigint,
    to_device_stream_id bigint,
    device_list_stream_id bigint
);
CREATE SEQUENCE application_services_txn_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE application_services_txns (
    as_id text NOT NULL,
    txn_id bigint NOT NULL,
    event_ids text NOT NULL
);
CREATE TABLE appservice_room_list (
    appservice_id text NOT NULL,
    network_id text NOT NULL,
    room_id text NOT NULL
);
CREATE TABLE appservice_stream_position (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    stream_ordering bigint,
    CONSTRAINT appservice_stream_position_lock_check CHECK ((lock = 'X'::bpchar))
);
CREATE TABLE batch_events (
    event_id text NOT NULL,
    room_id text NOT NULL,
    batch_id text NOT NULL
);
CREATE TABLE blocked_rooms (
    room_id text NOT NULL,
    user_id text NOT NULL
);
CREATE TABLE cache_invalidation_stream_by_instance (
    stream_id bigint NOT NULL,
    instance_name text NOT NULL,
    cache_func text NOT NULL,
    keys text[],
    invalidation_ts bigint
);
CREATE SEQUENCE cache_invalidation_stream_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE current_state_delta_stream (
    stream_id bigint NOT NULL,
    room_id text NOT NULL,
    type text NOT NULL,
    state_key text NOT NULL,
    event_id text,
    prev_event_id text,
    instance_name text
);
CREATE TABLE current_state_events (
    event_id text NOT NULL,
    room_id text NOT NULL,
    type text NOT NULL,
    state_key text NOT NULL,
    membership text
);
CREATE TABLE dehydrated_devices (
    user_id text NOT NULL,
    device_id text NOT NULL,
    device_data text NOT NULL
);
CREATE TABLE deleted_pushers (
    stream_id bigint NOT NULL,
    app_id text NOT NULL,
    pushkey text NOT NULL,
    user_id text NOT NULL
);
CREATE TABLE destination_rooms (
    destination text NOT NULL,
    room_id text NOT NULL,
    stream_ordering bigint NOT NULL
);
CREATE TABLE destinations (
    destination text NOT NULL,
    retry_last_ts bigint,
    retry_interval bigint,
    failure_ts bigint,
    last_successful_stream_ordering bigint
);
CREATE TABLE device_auth_providers (
    user_id text NOT NULL,
    device_id text NOT NULL,
    auth_provider_id text NOT NULL,
    auth_provider_session_id text NOT NULL
);
CREATE TABLE device_federation_inbox (
    origin text NOT NULL,
    message_id text NOT NULL,
    received_ts bigint NOT NULL,
    instance_name text
);
CREATE TABLE device_federation_outbox (
    destination text NOT NULL,
    stream_id bigint NOT NULL,
    queued_ts bigint NOT NULL,
    messages_json text NOT NULL,
    instance_name text
);
CREATE TABLE device_inbox (
    user_id text NOT NULL,
    device_id text NOT NULL,
    stream_id bigint NOT NULL,
    message_json text NOT NULL,
    instance_name text
);
CREATE SEQUENCE device_inbox_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE device_lists_changes_in_room (
    user_id text NOT NULL,
    device_id text NOT NULL,
    room_id text NOT NULL,
    stream_id bigint NOT NULL,
    converted_to_destinations boolean NOT NULL,
    opentracing_context text
);
CREATE TABLE device_lists_outbound_last_success (
    destination text NOT NULL,
    user_id text NOT NULL,
    stream_id bigint NOT NULL
);
CREATE TABLE device_lists_outbound_pokes (
    destination text NOT NULL,
    stream_id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text NOT NULL,
    sent boolean NOT NULL,
    ts bigint NOT NULL,
    opentracing_context text
);
CREATE TABLE device_lists_remote_cache (
    user_id text NOT NULL,
    device_id text NOT NULL,
    content text NOT NULL
);
CREATE TABLE device_lists_remote_extremeties (
    user_id text NOT NULL,
    stream_id text NOT NULL
);
CREATE TABLE device_lists_remote_resync (
    user_id text NOT NULL,
    added_ts bigint NOT NULL
);
CREATE TABLE device_lists_stream (
    stream_id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text NOT NULL
);
CREATE TABLE devices (
    user_id text NOT NULL,
    device_id text NOT NULL,
    display_name text,
    last_seen bigint,
    ip text,
    user_agent text,
    hidden boolean DEFAULT false
);
CREATE TABLE e2e_cross_signing_keys (
    user_id text NOT NULL,
    keytype text NOT NULL,
    keydata text NOT NULL,
    stream_id bigint NOT NULL
);
CREATE TABLE e2e_cross_signing_signatures (
    user_id text NOT NULL,
    key_id text NOT NULL,
    target_user_id text NOT NULL,
    target_device_id text NOT NULL,
    signature text NOT NULL
);
CREATE TABLE e2e_device_keys_json (
    user_id text NOT NULL,
    device_id text NOT NULL,
    ts_added_ms bigint NOT NULL,
    key_json text NOT NULL
);
CREATE TABLE e2e_fallback_keys_json (
    user_id text NOT NULL,
    device_id text NOT NULL,
    algorithm text NOT NULL,
    key_id text NOT NULL,
    key_json text NOT NULL,
    used boolean DEFAULT false NOT NULL
);
CREATE TABLE e2e_one_time_keys_json (
    user_id text NOT NULL,
    device_id text NOT NULL,
    algorithm text NOT NULL,
    key_id text NOT NULL,
    ts_added_ms bigint NOT NULL,
    key_json text NOT NULL
);
CREATE TABLE e2e_room_keys (
    user_id text NOT NULL,
    room_id text NOT NULL,
    session_id text NOT NULL,
    version bigint NOT NULL,
    first_message_index integer,
    forwarded_count integer,
    is_verified boolean,
    session_data text NOT NULL
);
CREATE TABLE e2e_room_keys_versions (
    user_id text NOT NULL,
    version bigint NOT NULL,
    algorithm text NOT NULL,
    auth_data text NOT NULL,
    deleted smallint DEFAULT 0 NOT NULL,
    etag bigint
);
CREATE TABLE erased_users (
    user_id text NOT NULL
);
CREATE TABLE event_auth (
    event_id text NOT NULL,
    auth_id text NOT NULL,
    room_id text NOT NULL
);
CREATE SEQUENCE event_auth_chain_id
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE event_auth_chain_links (
    origin_chain_id bigint NOT NULL,
    origin_sequence_number bigint NOT NULL,
    target_chain_id bigint NOT NULL,
    target_sequence_number bigint NOT NULL
);
CREATE TABLE event_auth_chain_to_calculate (
    event_id text NOT NULL,
    room_id text NOT NULL,
    type text NOT NULL,
    state_key text NOT NULL
);
CREATE TABLE event_auth_chains (
    event_id text NOT NULL,
    chain_id bigint NOT NULL,
    sequence_number bigint NOT NULL
);
CREATE TABLE event_backward_extremities (
    event_id text NOT NULL,
    room_id text NOT NULL
);
CREATE TABLE event_edges (
    event_id text NOT NULL,
    prev_event_id text NOT NULL,
    room_id text,
    is_state boolean DEFAULT false NOT NULL
);
CREATE TABLE event_expiry (
    event_id text NOT NULL,
    expiry_ts bigint NOT NULL
);
CREATE TABLE event_forward_extremities (
    event_id text NOT NULL,
    room_id text NOT NULL
);
CREATE TABLE event_json (
    event_id text NOT NULL,
    room_id text NOT NULL,
    internal_metadata text NOT NULL,
    json text NOT NULL,
    format_version integer
);
CREATE TABLE event_labels (
    event_id text NOT NULL,
    label text NOT NULL,
    room_id text NOT NULL,
    topological_ordering bigint NOT NULL
);
CREATE TABLE event_push_actions (
    room_id text NOT NULL,
    event_id text NOT NULL,
    user_id text NOT NULL,
    profile_tag character varying(32),
    actions text NOT NULL,
    topological_ordering bigint,
    stream_ordering bigint,
    notif smallint,
    highlight smallint,
    unread smallint,
    thread_id text
);
CREATE TABLE event_push_actions_staging (
    event_id text NOT NULL,
    user_id text NOT NULL,
    actions text NOT NULL,
    notif smallint NOT NULL,
    highlight smallint NOT NULL,
    unread smallint,
    thread_id text
);
CREATE TABLE event_push_summary (
    user_id text NOT NULL,
    room_id text NOT NULL,
    notif_count bigint NOT NULL,
    stream_ordering bigint NOT NULL,
    unread_count bigint,
    last_receipt_stream_ordering bigint,
    thread_id text
);
CREATE TABLE event_push_summary_last_receipt_stream_id (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    stream_id bigint NOT NULL,
    CONSTRAINT event_push_summary_last_receipt_stream_id_lock_check CHECK ((lock = 'X'::bpchar))
);
CREATE TABLE event_push_summary_stream_ordering (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    stream_ordering bigint NOT NULL,
    CONSTRAINT event_push_summary_stream_ordering_lock_check CHECK ((lock = 'X'::bpchar))
);
CREATE TABLE event_relations (
    event_id text NOT NULL,
    relates_to_id text NOT NULL,
    relation_type text NOT NULL,
    aggregation_key text
);
CREATE TABLE event_reports (
    id bigint NOT NULL,
    received_ts bigint NOT NULL,
    room_id text NOT NULL,
    event_id text NOT NULL,
    user_id text NOT NULL,
    reason text,
    content text
);
CREATE TABLE event_search (
    event_id text,
    room_id text,
    sender text,
    key text,
    vector tsvector,
    origin_server_ts bigint,
    stream_ordering bigint
);
CREATE TABLE event_to_state_groups (
    event_id text NOT NULL,
    state_group bigint NOT NULL
);
CREATE TABLE event_txn_id (
    event_id text NOT NULL,
    room_id text NOT NULL,
    user_id text NOT NULL,
    token_id bigint NOT NULL,
    txn_id text NOT NULL,
    inserted_ts bigint NOT NULL
);
CREATE TABLE events (
    topological_ordering bigint NOT NULL,
    event_id text NOT NULL,
    type text NOT NULL,
    room_id text NOT NULL,
    content text,
    unrecognized_keys text,
    processed boolean NOT NULL,
    outlier boolean NOT NULL,
    depth bigint DEFAULT 0 NOT NULL,
    origin_server_ts bigint,
    received_ts bigint,
    sender text,
    contains_url boolean,
    instance_name text,
    stream_ordering bigint,
    state_key text,
    rejection_reason text
);
CREATE SEQUENCE events_backfill_stream_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE SEQUENCE events_stream_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE ex_outlier_stream (
    event_stream_ordering bigint NOT NULL,
    event_id text NOT NULL,
    state_group bigint NOT NULL,
    instance_name text
);
CREATE TABLE federation_inbound_events_staging (
    origin text NOT NULL,
    room_id text NOT NULL,
    event_id text NOT NULL,
    received_ts bigint NOT NULL,
    event_json text NOT NULL,
    internal_metadata text NOT NULL
);
CREATE TABLE federation_stream_position (
    type text NOT NULL,
    stream_id bigint NOT NULL,
    instance_name text DEFAULT 'master'::text NOT NULL
);
CREATE TABLE ignored_users (
    ignorer_user_id text NOT NULL,
    ignored_user_id text NOT NULL
);
CREATE TABLE insertion_event_edges (
    event_id text NOT NULL,
    room_id text NOT NULL,
    insertion_prev_event_id text NOT NULL
);
CREATE TABLE insertion_event_extremities (
    event_id text NOT NULL,
    room_id text NOT NULL
);
CREATE TABLE insertion_events (
    event_id text NOT NULL,
    room_id text NOT NULL,
    next_batch_id text NOT NULL
);
CREATE TABLE instance_map (
    instance_id integer NOT NULL,
    instance_name text NOT NULL
);
CREATE SEQUENCE instance_map_instance_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
ALTER SEQUENCE instance_map_instance_id_seq OWNED BY instance_map.instance_id;
CREATE TABLE local_current_membership (
    room_id text NOT NULL,
    user_id text NOT NULL,
    event_id text NOT NULL,
    membership text NOT NULL
);
CREATE TABLE local_media_repository (
    media_id text,
    media_type text,
    media_length integer,
    created_ts bigint,
    upload_name text,
    user_id text,
    quarantined_by text,
    url_cache text,
    last_access_ts bigint,
    safe_from_quarantine boolean DEFAULT false NOT NULL
);
CREATE TABLE local_media_repository_thumbnails (
    media_id text,
    thumbnail_width integer,
    thumbnail_height integer,
    thumbnail_type text,
    thumbnail_method text,
    thumbnail_length integer
);
CREATE TABLE local_media_repository_url_cache (
    url text,
    response_code integer,
    etag text,
    expires_ts bigint,
    og text,
    media_id text,
    download_ts bigint
);
CREATE TABLE monthly_active_users (
    user_id text NOT NULL,
    "timestamp" bigint NOT NULL
);
CREATE TABLE open_id_tokens (
    token text NOT NULL,
    ts_valid_until_ms bigint NOT NULL,
    user_id text NOT NULL
);
CREATE TABLE partial_state_events (
    room_id text NOT NULL,
    event_id text NOT NULL
);
CREATE TABLE partial_state_rooms (
    room_id text NOT NULL
);
CREATE TABLE partial_state_rooms_servers (
    room_id text NOT NULL,
    server_name text NOT NULL
);
CREATE TABLE presence (
    user_id text NOT NULL,
    state character varying(20),
    status_msg text,
    mtime bigint
);
CREATE TABLE presence_stream (
    stream_id bigint,
    user_id text,
    state text,
    last_active_ts bigint,
    last_federation_update_ts bigint,
    last_user_sync_ts bigint,
    status_msg text,
    currently_active boolean,
    instance_name text
);
CREATE SEQUENCE presence_stream_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE profiles (
    user_id text NOT NULL,
    displayname text,
    avatar_url text
);
CREATE TABLE push_rules (
    id bigint NOT NULL,
    user_name text NOT NULL,
    rule_id text NOT NULL,
    priority_class smallint NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    conditions text NOT NULL,
    actions text NOT NULL
);
CREATE TABLE push_rules_enable (
    id bigint NOT NULL,
    user_name text NOT NULL,
    rule_id text NOT NULL,
    enabled smallint
);
CREATE TABLE push_rules_stream (
    stream_id bigint NOT NULL,
    event_stream_ordering bigint NOT NULL,
    user_id text NOT NULL,
    rule_id text NOT NULL,
    op text NOT NULL,
    priority_class smallint,
    priority integer,
    conditions text,
    actions text
);
CREATE TABLE pusher_throttle (
    pusher bigint NOT NULL,
    room_id text NOT NULL,
    last_sent_ts bigint,
    throttle_ms bigint
);
CREATE TABLE pushers (
    id bigint NOT NULL,
    user_name text NOT NULL,
    access_token bigint,
    profile_tag text NOT NULL,
    kind text NOT NULL,
    app_id text NOT NULL,
    app_display_name text NOT NULL,
    device_display_name text NOT NULL,
    pushkey text NOT NULL,
    ts bigint NOT NULL,
    lang text,
    data text,
    last_stream_ordering bigint,
    last_success bigint,
    failing_since bigint
);
CREATE TABLE ratelimit_override (
    user_id text NOT NULL,
    messages_per_second bigint,
    burst_count bigint
);
CREATE TABLE receipts_graph (
    room_id text NOT NULL,
    receipt_type text NOT NULL,
    user_id text NOT NULL,
    event_ids text NOT NULL,
    data text NOT NULL,
    thread_id text
);
CREATE TABLE receipts_linearized (
    stream_id bigint NOT NULL,
    room_id text NOT NULL,
    receipt_type text NOT NULL,
    user_id text NOT NULL,
    event_id text NOT NULL,
    data text NOT NULL,
    instance_name text,
    event_stream_ordering bigint,
    thread_id text
);
CREATE SEQUENCE receipts_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE received_transactions (
    transaction_id text,
    origin text,
    ts bigint,
    response_code integer,
    response_json bytea,
    has_been_referenced smallint DEFAULT 0
);
CREATE TABLE redactions (
    event_id text NOT NULL,
    redacts text NOT NULL,
    have_censored boolean DEFAULT false NOT NULL,
    received_ts bigint
);
CREATE TABLE refresh_tokens (
    id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text NOT NULL,
    token text NOT NULL,
    next_token_id bigint,
    expiry_ts bigint,
    ultimate_session_expiry_ts bigint
);
CREATE TABLE registration_tokens (
    token text NOT NULL,
    uses_allowed integer,
    pending integer NOT NULL,
    completed integer NOT NULL,
    expiry_time bigint
);
CREATE TABLE rejections (
    event_id text NOT NULL,
    reason text NOT NULL,
    last_check text NOT NULL
);
CREATE TABLE remote_media_cache (
    media_origin text,
    media_id text,
    media_type text,
    created_ts bigint,
    upload_name text,
    media_length integer,
    filesystem_id text,
    last_access_ts bigint,
    quarantined_by text
);
CREATE TABLE remote_media_cache_thumbnails (
    media_origin text,
    media_id text,
    thumbnail_width integer,
    thumbnail_height integer,
    thumbnail_method text,
    thumbnail_type text,
    thumbnail_length integer,
    filesystem_id text
);
CREATE TABLE room_account_data (
    user_id text NOT NULL,
    room_id text NOT NULL,
    account_data_type text NOT NULL,
    stream_id bigint NOT NULL,
    content text NOT NULL,
    instance_name text
);
CREATE TABLE room_alias_servers (
    room_alias text NOT NULL,
    server text NOT NULL
);
CREATE TABLE room_aliases (
    room_alias text NOT NULL,
    room_id text NOT NULL,
    creator text
);
CREATE TABLE room_depth (
    room_id text NOT NULL,
    min_depth bigint
);
CREATE TABLE room_memberships (
    event_id text NOT NULL,
    user_id text NOT NULL,
    sender text NOT NULL,
    room_id text NOT NULL,
    membership text NOT NULL,
    forgotten integer DEFAULT 0,
    display_name text,
    avatar_url text
);
CREATE TABLE room_retention (
    room_id text NOT NULL,
    event_id text NOT NULL,
    min_lifetime bigint,
    max_lifetime bigint
);
CREATE TABLE room_stats_current (
    room_id text NOT NULL,
    current_state_events integer NOT NULL,
    joined_members integer NOT NULL,
    invited_members integer NOT NULL,
    left_members integer NOT NULL,
    banned_members integer NOT NULL,
    local_users_in_room integer NOT NULL,
    completed_delta_stream_id bigint NOT NULL,
    knocked_members integer
);
CREATE TABLE room_stats_earliest_token (
    room_id text NOT NULL,
    token bigint NOT NULL
);
CREATE TABLE room_stats_state (
    room_id text NOT NULL,
    name text,
    canonical_alias text,
    join_rules text,
    history_visibility text,
    encryption text,
    avatar text,
    guest_access text,
    is_federatable boolean,
    topic text,
    room_type text
);
CREATE TABLE room_tags (
    user_id text NOT NULL,
    room_id text NOT NULL,
    tag text NOT NULL,
    content text NOT NULL
);
CREATE TABLE room_tags_revisions (
    user_id text NOT NULL,
    room_id text NOT NULL,
    stream_id bigint NOT NULL,
    instance_name text
);
CREATE TABLE rooms (
    room_id text NOT NULL,
    is_public boolean,
    creator text,
    room_version text,
    has_auth_chain_index boolean
);
CREATE TABLE server_keys_json (
    server_name text NOT NULL,
    key_id text NOT NULL,
    from_server text NOT NULL,
    ts_added_ms bigint NOT NULL,
    ts_valid_until_ms bigint NOT NULL,
    key_json bytea NOT NULL
);
CREATE TABLE server_signature_keys (
    server_name text,
    key_id text,
    from_server text,
    ts_added_ms bigint,
    verify_key bytea,
    ts_valid_until_ms bigint
);
CREATE TABLE sessions (
    session_type text NOT NULL,
    session_id text NOT NULL,
    value text NOT NULL,
    expiry_time_ms bigint NOT NULL
);
CREATE TABLE state_events (
    event_id text NOT NULL,
    room_id text NOT NULL,
    type text NOT NULL,
    state_key text NOT NULL,
    prev_state text
);
CREATE TABLE stats_incremental_position (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    stream_id bigint NOT NULL,
    CONSTRAINT stats_incremental_position_lock_check CHECK ((lock = 'X'::bpchar))
);
CREATE TABLE stream_ordering_to_exterm (
    stream_ordering bigint NOT NULL,
    room_id text NOT NULL,
    event_id text NOT NULL
);
CREATE TABLE stream_positions (
    stream_name text NOT NULL,
    instance_name text NOT NULL,
    stream_id bigint NOT NULL
);
CREATE TABLE threepid_guest_access_tokens (
    medium text,
    address text,
    guest_access_token text,
    first_inviter text
);
CREATE TABLE threepid_validation_session (
    session_id text NOT NULL,
    medium text NOT NULL,
    address text NOT NULL,
    client_secret text NOT NULL,
    last_send_attempt bigint NOT NULL,
    validated_at bigint
);
CREATE TABLE threepid_validation_token (
    token text NOT NULL,
    session_id text NOT NULL,
    next_link text,
    expires bigint NOT NULL
);
CREATE TABLE ui_auth_sessions (
    session_id text NOT NULL,
    creation_time bigint NOT NULL,
    serverdict text NOT NULL,
    clientdict text NOT NULL,
    uri text NOT NULL,
    method text NOT NULL,
    description text NOT NULL
);
CREATE TABLE ui_auth_sessions_credentials (
    session_id text NOT NULL,
    stage_type text NOT NULL,
    result text NOT NULL
);
CREATE TABLE ui_auth_sessions_ips (
    session_id text NOT NULL,
    ip text NOT NULL,
    user_agent text NOT NULL
);
CREATE TABLE user_daily_visits (
    user_id text NOT NULL,
    device_id text,
    "timestamp" bigint NOT NULL,
    user_agent text
);
CREATE TABLE user_directory (
    user_id text NOT NULL,
    room_id text,
    display_name text,
    avatar_url text
);
CREATE TABLE user_directory_search (
    user_id text NOT NULL,
    vector tsvector
);
CREATE TABLE user_directory_stream_pos (
    lock character(1) DEFAULT 'X'::bpchar NOT NULL,
    stream_id bigint,
    CONSTRAINT user_directory_stream_pos_lock_check CHECK ((lock = 'X'::bpchar))
);
CREATE TABLE user_external_ids (
    auth_provider text NOT NULL,
    external_id text NOT NULL,
    user_id text NOT NULL
);
CREATE TABLE user_filters (
    user_id text NOT NULL,
    filter_id bigint NOT NULL,
    filter_json bytea NOT NULL
);
CREATE SEQUENCE user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
CREATE TABLE user_ips (
    user_id text NOT NULL,
    access_token text NOT NULL,
    device_id text,
    ip text NOT NULL,
    user_agent text NOT NULL,
    last_seen bigint NOT NULL
);
CREATE TABLE user_signature_stream (
    stream_id bigint NOT NULL,
    from_user_id text NOT NULL,
    user_ids text NOT NULL
);
CREATE TABLE user_stats_current (
    user_id text NOT NULL,
    joined_rooms bigint NOT NULL,
    completed_delta_stream_id bigint NOT NULL
);
CREATE TABLE user_threepid_id_server (
    user_id text NOT NULL,
    medium text NOT NULL,
    address text NOT NULL,
    id_server text NOT NULL
);
CREATE TABLE user_threepids (
    user_id text NOT NULL,
    medium text NOT NULL,
    address text NOT NULL,
    validated_at bigint NOT NULL,
    added_at bigint NOT NULL
);
CREATE TABLE users (
    name text,
    password_hash text,
    creation_ts bigint,
    admin smallint DEFAULT 0 NOT NULL,
    upgrade_ts bigint,
    is_guest smallint DEFAULT 0 NOT NULL,
    appservice_id text,
    consent_version text,
    consent_server_notice_sent text,
    user_type text,
    deactivated smallint DEFAULT 0 NOT NULL,
    shadow_banned boolean,
    consent_ts bigint
);
CREATE TABLE users_in_public_rooms (
    user_id text NOT NULL,
    room_id text NOT NULL
);
CREATE TABLE users_pending_deactivation (
    user_id text NOT NULL
);
CREATE TABLE users_to_send_full_presence_to (
    user_id text NOT NULL,
    presence_stream_id bigint
);
CREATE TABLE users_who_share_private_rooms (
    user_id text NOT NULL,
    other_user_id text NOT NULL,
    room_id text NOT NULL
);
CREATE TABLE worker_locks (
    lock_name text NOT NULL,
    lock_key text NOT NULL,
    instance_name text NOT NULL,
    token text NOT NULL,
    last_renewed_ts bigint NOT NULL
);
ALTER TABLE ONLY instance_map ALTER COLUMN instance_id SET DEFAULT nextval('instance_map_instance_id_seq'::regclass);
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_token_key UNIQUE (token);
ALTER TABLE ONLY account_data
    ADD CONSTRAINT account_data_uniqueness UNIQUE (user_id, account_data_type);
ALTER TABLE ONLY account_validity
    ADD CONSTRAINT account_validity_pkey PRIMARY KEY (user_id);
ALTER TABLE ONLY application_services_state
    ADD CONSTRAINT application_services_state_pkey PRIMARY KEY (as_id);
ALTER TABLE ONLY application_services_txns
    ADD CONSTRAINT application_services_txns_as_id_txn_id_key UNIQUE (as_id, txn_id);
ALTER TABLE ONLY appservice_stream_position
    ADD CONSTRAINT appservice_stream_position_lock_key UNIQUE (lock);
ALTER TABLE ONLY current_state_events
    ADD CONSTRAINT current_state_events_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY current_state_events
    ADD CONSTRAINT current_state_events_room_id_type_state_key_key UNIQUE (room_id, type, state_key);
ALTER TABLE ONLY dehydrated_devices
    ADD CONSTRAINT dehydrated_devices_pkey PRIMARY KEY (user_id);
ALTER TABLE ONLY destination_rooms
    ADD CONSTRAINT destination_rooms_pkey PRIMARY KEY (destination, room_id);
ALTER TABLE ONLY destinations
    ADD CONSTRAINT destinations_pkey PRIMARY KEY (destination);
ALTER TABLE ONLY devices
    ADD CONSTRAINT device_uniqueness UNIQUE (user_id, device_id);
ALTER TABLE ONLY e2e_device_keys_json
    ADD CONSTRAINT e2e_device_keys_json_uniqueness UNIQUE (user_id, device_id);
ALTER TABLE ONLY e2e_fallback_keys_json
    ADD CONSTRAINT e2e_fallback_keys_json_uniqueness UNIQUE (user_id, device_id, algorithm);
ALTER TABLE ONLY e2e_one_time_keys_json
    ADD CONSTRAINT e2e_one_time_keys_json_uniqueness UNIQUE (user_id, device_id, algorithm, key_id);
ALTER TABLE ONLY event_auth_chain_to_calculate
    ADD CONSTRAINT event_auth_chain_to_calculate_pkey PRIMARY KEY (event_id);
ALTER TABLE ONLY event_auth_chains
    ADD CONSTRAINT event_auth_chains_pkey PRIMARY KEY (event_id);
ALTER TABLE ONLY event_backward_extremities
    ADD CONSTRAINT event_backward_extremities_event_id_room_id_key UNIQUE (event_id, room_id);
ALTER TABLE ONLY event_expiry
    ADD CONSTRAINT event_expiry_pkey PRIMARY KEY (event_id);
ALTER TABLE ONLY event_forward_extremities
    ADD CONSTRAINT event_forward_extremities_event_id_room_id_key UNIQUE (event_id, room_id);
ALTER TABLE ONLY event_push_actions
    ADD CONSTRAINT event_id_user_id_profile_tag_uniqueness UNIQUE (room_id, event_id, user_id, profile_tag);
ALTER TABLE ONLY event_json
    ADD CONSTRAINT event_json_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY event_labels
    ADD CONSTRAINT event_labels_pkey PRIMARY KEY (event_id, label);
ALTER TABLE ONLY event_push_summary_last_receipt_stream_id
    ADD CONSTRAINT event_push_summary_last_receipt_stream_id_lock_key UNIQUE (lock);
ALTER TABLE ONLY event_push_summary_stream_ordering
    ADD CONSTRAINT event_push_summary_stream_ordering_lock_key UNIQUE (lock);
ALTER TABLE ONLY event_reports
    ADD CONSTRAINT event_reports_pkey PRIMARY KEY (id);
ALTER TABLE ONLY event_to_state_groups
    ADD CONSTRAINT event_to_state_groups_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY events
    ADD CONSTRAINT events_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY ex_outlier_stream
    ADD CONSTRAINT ex_outlier_stream_pkey PRIMARY KEY (event_stream_ordering);
ALTER TABLE ONLY instance_map
    ADD CONSTRAINT instance_map_pkey PRIMARY KEY (instance_id);
ALTER TABLE ONLY local_media_repository
    ADD CONSTRAINT local_media_repository_media_id_key UNIQUE (media_id);
ALTER TABLE ONLY user_threepids
    ADD CONSTRAINT medium_address UNIQUE (medium, address);
ALTER TABLE ONLY open_id_tokens
    ADD CONSTRAINT open_id_tokens_pkey PRIMARY KEY (token);
ALTER TABLE ONLY partial_state_events
    ADD CONSTRAINT partial_state_events_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY partial_state_rooms
    ADD CONSTRAINT partial_state_rooms_pkey PRIMARY KEY (room_id);
ALTER TABLE ONLY partial_state_rooms_servers
    ADD CONSTRAINT partial_state_rooms_servers_room_id_server_name_key UNIQUE (room_id, server_name);
ALTER TABLE ONLY presence
    ADD CONSTRAINT presence_user_id_key UNIQUE (user_id);
ALTER TABLE ONLY profiles
    ADD CONSTRAINT profiles_user_id_key UNIQUE (user_id);
ALTER TABLE ONLY push_rules_enable
    ADD CONSTRAINT push_rules_enable_pkey PRIMARY KEY (id);
ALTER TABLE ONLY push_rules_enable
    ADD CONSTRAINT push_rules_enable_user_name_rule_id_key UNIQUE (user_name, rule_id);
ALTER TABLE ONLY push_rules
    ADD CONSTRAINT push_rules_pkey PRIMARY KEY (id);
ALTER TABLE ONLY push_rules
    ADD CONSTRAINT push_rules_user_name_rule_id_key UNIQUE (user_name, rule_id);
ALTER TABLE ONLY pusher_throttle
    ADD CONSTRAINT pusher_throttle_pkey PRIMARY KEY (pusher, room_id);
ALTER TABLE ONLY pushers
    ADD CONSTRAINT pushers2_app_id_pushkey_user_name_key UNIQUE (app_id, pushkey, user_name);
ALTER TABLE ONLY pushers
    ADD CONSTRAINT pushers2_pkey PRIMARY KEY (id);
ALTER TABLE ONLY receipts_graph
    ADD CONSTRAINT receipts_graph_uniqueness UNIQUE (room_id, receipt_type, user_id);
ALTER TABLE ONLY receipts_graph
    ADD CONSTRAINT receipts_graph_uniqueness_thread UNIQUE (room_id, receipt_type, user_id, thread_id);
ALTER TABLE ONLY receipts_linearized
    ADD CONSTRAINT receipts_linearized_uniqueness UNIQUE (room_id, receipt_type, user_id);
ALTER TABLE ONLY receipts_linearized
    ADD CONSTRAINT receipts_linearized_uniqueness_thread UNIQUE (room_id, receipt_type, user_id, thread_id);
ALTER TABLE ONLY received_transactions
    ADD CONSTRAINT received_transactions_transaction_id_origin_key UNIQUE (transaction_id, origin);
ALTER TABLE ONLY redactions
    ADD CONSTRAINT redactions_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_key UNIQUE (token);
ALTER TABLE ONLY registration_tokens
    ADD CONSTRAINT registration_tokens_token_key UNIQUE (token);
ALTER TABLE ONLY rejections
    ADD CONSTRAINT rejections_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY remote_media_cache
    ADD CONSTRAINT remote_media_cache_media_origin_media_id_key UNIQUE (media_origin, media_id);
ALTER TABLE ONLY room_account_data
    ADD CONSTRAINT room_account_data_uniqueness UNIQUE (user_id, room_id, account_data_type);
ALTER TABLE ONLY room_aliases
    ADD CONSTRAINT room_aliases_room_alias_key UNIQUE (room_alias);
ALTER TABLE ONLY room_depth
    ADD CONSTRAINT room_depth_room_id_key UNIQUE (room_id);
ALTER TABLE ONLY room_memberships
    ADD CONSTRAINT room_memberships_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY room_retention
    ADD CONSTRAINT room_retention_pkey PRIMARY KEY (room_id, event_id);
ALTER TABLE ONLY room_stats_current
    ADD CONSTRAINT room_stats_current_pkey PRIMARY KEY (room_id);
ALTER TABLE ONLY room_tags_revisions
    ADD CONSTRAINT room_tag_revisions_uniqueness UNIQUE (user_id, room_id);
ALTER TABLE ONLY room_tags
    ADD CONSTRAINT room_tag_uniqueness UNIQUE (user_id, room_id, tag);
ALTER TABLE ONLY rooms
    ADD CONSTRAINT rooms_pkey PRIMARY KEY (room_id);
ALTER TABLE ONLY server_keys_json
    ADD CONSTRAINT server_keys_json_uniqueness UNIQUE (server_name, key_id, from_server);
ALTER TABLE ONLY server_signature_keys
    ADD CONSTRAINT server_signature_keys_server_name_key_id_key UNIQUE (server_name, key_id);
ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_session_type_session_id_key UNIQUE (session_type, session_id);
ALTER TABLE ONLY state_events
    ADD CONSTRAINT state_events_event_id_key UNIQUE (event_id);
ALTER TABLE ONLY stats_incremental_position
    ADD CONSTRAINT stats_incremental_position_lock_key UNIQUE (lock);
ALTER TABLE ONLY threepid_validation_session
    ADD CONSTRAINT threepid_validation_session_pkey PRIMARY KEY (session_id);
ALTER TABLE ONLY threepid_validation_token
    ADD CONSTRAINT threepid_validation_token_pkey PRIMARY KEY (token);
ALTER TABLE ONLY ui_auth_sessions_credentials
    ADD CONSTRAINT ui_auth_sessions_credentials_session_id_stage_type_key UNIQUE (session_id, stage_type);
ALTER TABLE ONLY ui_auth_sessions_ips
    ADD CONSTRAINT ui_auth_sessions_ips_session_id_ip_user_agent_key UNIQUE (session_id, ip, user_agent);
ALTER TABLE ONLY ui_auth_sessions
    ADD CONSTRAINT ui_auth_sessions_session_id_key UNIQUE (session_id);
ALTER TABLE ONLY user_directory_stream_pos
    ADD CONSTRAINT user_directory_stream_pos_lock_key UNIQUE (lock);
ALTER TABLE ONLY user_external_ids
    ADD CONSTRAINT user_external_ids_auth_provider_external_id_key UNIQUE (auth_provider, external_id);
ALTER TABLE ONLY user_stats_current
    ADD CONSTRAINT user_stats_current_pkey PRIMARY KEY (user_id);
ALTER TABLE ONLY users
    ADD CONSTRAINT users_name_key UNIQUE (name);
ALTER TABLE ONLY users_to_send_full_presence_to
    ADD CONSTRAINT users_to_send_full_presence_to_pkey PRIMARY KEY (user_id);
CREATE INDEX access_tokens_device_id ON access_tokens USING btree (user_id, device_id);
CREATE INDEX account_data_stream_id ON account_data USING btree (user_id, stream_id);
CREATE INDEX application_services_txns_id ON application_services_txns USING btree (as_id);
CREATE UNIQUE INDEX appservice_room_list_idx ON appservice_room_list USING btree (appservice_id, network_id, room_id);
CREATE INDEX batch_events_batch_id ON batch_events USING btree (batch_id);
CREATE UNIQUE INDEX blocked_rooms_idx ON blocked_rooms USING btree (room_id);
CREATE UNIQUE INDEX cache_invalidation_stream_by_instance_id ON cache_invalidation_stream_by_instance USING btree (stream_id);
CREATE INDEX cache_invalidation_stream_by_instance_instance_index ON cache_invalidation_stream_by_instance USING btree (instance_name, stream_id);
CREATE UNIQUE INDEX chunk_events_event_id ON batch_events USING btree (event_id);
CREATE INDEX current_state_delta_stream_idx ON current_state_delta_stream USING btree (stream_id);
CREATE INDEX current_state_events_member_index ON current_state_events USING btree (state_key) WHERE (type = 'm.room.member'::text);
CREATE INDEX deleted_pushers_stream_id ON deleted_pushers USING btree (stream_id);
CREATE INDEX destination_rooms_room_id ON destination_rooms USING btree (room_id);
CREATE INDEX device_auth_providers_devices ON device_auth_providers USING btree (user_id, device_id);
CREATE INDEX device_auth_providers_sessions ON device_auth_providers USING btree (auth_provider_id, auth_provider_session_id);
CREATE INDEX device_federation_inbox_sender_id ON device_federation_inbox USING btree (origin, message_id);
CREATE INDEX device_federation_outbox_destination_id ON device_federation_outbox USING btree (destination, stream_id);
CREATE INDEX device_federation_outbox_id ON device_federation_outbox USING btree (stream_id);
CREATE INDEX device_inbox_stream_id_user_id ON device_inbox USING btree (stream_id, user_id);
CREATE INDEX device_inbox_user_stream_id ON device_inbox USING btree (user_id, device_id, stream_id);
CREATE UNIQUE INDEX device_lists_changes_in_stream_id ON device_lists_changes_in_room USING btree (stream_id, room_id);
CREATE INDEX device_lists_changes_in_stream_id_unconverted ON device_lists_changes_in_room USING btree (stream_id) WHERE (NOT converted_to_destinations);
CREATE UNIQUE INDEX device_lists_outbound_last_success_unique_idx ON device_lists_outbound_last_success USING btree (destination, user_id);
CREATE INDEX device_lists_outbound_pokes_id ON device_lists_outbound_pokes USING btree (destination, stream_id);
CREATE INDEX device_lists_outbound_pokes_stream ON device_lists_outbound_pokes USING btree (stream_id);
CREATE INDEX device_lists_outbound_pokes_user ON device_lists_outbound_pokes USING btree (destination, user_id);
CREATE UNIQUE INDEX device_lists_remote_cache_unique_id ON device_lists_remote_cache USING btree (user_id, device_id);
CREATE UNIQUE INDEX device_lists_remote_extremeties_unique_idx ON device_lists_remote_extremeties USING btree (user_id);
CREATE UNIQUE INDEX device_lists_remote_resync_idx ON device_lists_remote_resync USING btree (user_id);
CREATE INDEX device_lists_remote_resync_ts_idx ON device_lists_remote_resync USING btree (added_ts);
CREATE INDEX device_lists_stream_id ON device_lists_stream USING btree (stream_id, user_id);
CREATE INDEX device_lists_stream_user_id ON device_lists_stream USING btree (user_id, device_id);
CREATE UNIQUE INDEX e2e_cross_signing_keys_idx ON e2e_cross_signing_keys USING btree (user_id, keytype, stream_id);
CREATE UNIQUE INDEX e2e_cross_signing_keys_stream_idx ON e2e_cross_signing_keys USING btree (stream_id);
CREATE INDEX e2e_cross_signing_signatures2_idx ON e2e_cross_signing_signatures USING btree (user_id, target_user_id, target_device_id);
CREATE UNIQUE INDEX e2e_room_keys_versions_idx ON e2e_room_keys_versions USING btree (user_id, version);
CREATE UNIQUE INDEX e2e_room_keys_with_version_idx ON e2e_room_keys USING btree (user_id, version, room_id, session_id);
CREATE UNIQUE INDEX erased_users_user ON erased_users USING btree (user_id);
CREATE INDEX ev_b_extrem_id ON event_backward_extremities USING btree (event_id);
CREATE INDEX ev_b_extrem_room ON event_backward_extremities USING btree (room_id);
CREATE INDEX ev_edges_prev_id ON event_edges USING btree (prev_event_id);
CREATE INDEX ev_extrem_id ON event_forward_extremities USING btree (event_id);
CREATE INDEX ev_extrem_room ON event_forward_extremities USING btree (room_id);
CREATE INDEX evauth_edges_id ON event_auth USING btree (event_id);
CREATE INDEX event_auth_chain_links_idx ON event_auth_chain_links USING btree (origin_chain_id, target_chain_id);
CREATE INDEX event_auth_chain_to_calculate_rm_id ON event_auth_chain_to_calculate USING btree (room_id);
CREATE UNIQUE INDEX event_auth_chains_c_seq_index ON event_auth_chains USING btree (chain_id, sequence_number);
CREATE INDEX event_contains_url_index ON events USING btree (room_id, topological_ordering, stream_ordering) WHERE ((contains_url = true) AND (outlier = false));
CREATE UNIQUE INDEX event_edges_event_id_prev_event_id_idx ON event_edges USING btree (event_id, prev_event_id);
CREATE INDEX event_expiry_expiry_ts_idx ON event_expiry USING btree (expiry_ts);
CREATE INDEX event_labels_room_id_label_idx ON event_labels USING btree (room_id, label, topological_ordering);
CREATE INDEX event_push_actions_highlights_index ON event_push_actions USING btree (user_id, room_id, topological_ordering, stream_ordering) WHERE (highlight = 1);
CREATE INDEX event_push_actions_rm_tokens ON event_push_actions USING btree (user_id, room_id, topological_ordering, stream_ordering);
CREATE INDEX event_push_actions_room_id_user_id ON event_push_actions USING btree (room_id, user_id);
CREATE INDEX event_push_actions_staging_id ON event_push_actions_staging USING btree (event_id);
CREATE INDEX event_push_actions_stream_highlight_index ON event_push_actions USING btree (highlight, stream_ordering) WHERE (highlight = 0);
CREATE INDEX event_push_actions_stream_ordering ON event_push_actions USING btree (stream_ordering, user_id);
CREATE INDEX event_push_actions_u_highlight ON event_push_actions USING btree (user_id, stream_ordering);
CREATE UNIQUE INDEX event_push_summary_unique_index ON event_push_summary USING btree (user_id, room_id);
CREATE UNIQUE INDEX event_push_summary_unique_index2 ON event_push_summary USING btree (user_id, room_id, thread_id);
CREATE UNIQUE INDEX event_relations_id ON event_relations USING btree (event_id);
CREATE INDEX event_relations_relates ON event_relations USING btree (relates_to_id, relation_type, aggregation_key);
CREATE INDEX event_search_ev_ridx ON event_search USING btree (room_id);
CREATE UNIQUE INDEX event_search_event_id_idx ON event_search USING btree (event_id);
CREATE INDEX event_search_fts_idx ON event_search USING gin (vector);
CREATE INDEX event_to_state_groups_sg_index ON event_to_state_groups USING btree (state_group);
CREATE UNIQUE INDEX event_txn_id_event_id ON event_txn_id USING btree (event_id);
CREATE INDEX event_txn_id_ts ON event_txn_id USING btree (inserted_ts);
CREATE UNIQUE INDEX event_txn_id_txn_id ON event_txn_id USING btree (room_id, user_id, token_id, txn_id);
CREATE INDEX events_order_room ON events USING btree (room_id, topological_ordering, stream_ordering);
CREATE INDEX events_room_stream ON events USING btree (room_id, stream_ordering);
CREATE UNIQUE INDEX events_stream_ordering ON events USING btree (stream_ordering);
CREATE INDEX events_ts ON events USING btree (origin_server_ts, stream_ordering);
CREATE UNIQUE INDEX federation_inbound_events_staging_instance_event ON federation_inbound_events_staging USING btree (origin, event_id);
CREATE INDEX federation_inbound_events_staging_room ON federation_inbound_events_staging USING btree (room_id, received_ts);
CREATE UNIQUE INDEX federation_stream_position_instance ON federation_stream_position USING btree (type, instance_name);
CREATE INDEX ignored_users_ignored_user_id ON ignored_users USING btree (ignored_user_id);
CREATE UNIQUE INDEX ignored_users_uniqueness ON ignored_users USING btree (ignorer_user_id, ignored_user_id);
CREATE INDEX insertion_event_edges_event_id ON insertion_event_edges USING btree (event_id);
CREATE INDEX insertion_event_edges_insertion_prev_event_id ON insertion_event_edges USING btree (insertion_prev_event_id);
CREATE INDEX insertion_event_edges_insertion_room_id ON insertion_event_edges USING btree (room_id);
CREATE UNIQUE INDEX insertion_event_extremities_event_id ON insertion_event_extremities USING btree (event_id);
CREATE INDEX insertion_event_extremities_room_id ON insertion_event_extremities USING btree (room_id);
CREATE UNIQUE INDEX insertion_events_event_id ON insertion_events USING btree (event_id);
CREATE INDEX insertion_events_next_batch_id ON insertion_events USING btree (next_batch_id);
CREATE UNIQUE INDEX instance_map_idx ON instance_map USING btree (instance_name);
CREATE UNIQUE INDEX local_current_membership_idx ON local_current_membership USING btree (user_id, room_id);
CREATE INDEX local_current_membership_room_idx ON local_current_membership USING btree (room_id);
CREATE UNIQUE INDEX local_media_repository_thumbn_media_id_width_height_method_key ON local_media_repository_thumbnails USING btree (media_id, thumbnail_width, thumbnail_height, thumbnail_type, thumbnail_method);
CREATE INDEX local_media_repository_thumbnails_media_id ON local_media_repository_thumbnails USING btree (media_id);
CREATE INDEX local_media_repository_url_cache_by_url_download_ts ON local_media_repository_url_cache USING btree (url, download_ts);
CREATE INDEX local_media_repository_url_cache_expires_idx ON local_media_repository_url_cache USING btree (expires_ts);
CREATE INDEX local_media_repository_url_cache_media_idx ON local_media_repository_url_cache USING btree (media_id);
CREATE INDEX local_media_repository_url_idx ON local_media_repository USING btree (created_ts) WHERE (url_cache IS NOT NULL);
CREATE INDEX monthly_active_users_time_stamp ON monthly_active_users USING btree ("timestamp");
CREATE UNIQUE INDEX monthly_active_users_users ON monthly_active_users USING btree (user_id);
CREATE INDEX open_id_tokens_ts_valid_until_ms ON open_id_tokens USING btree (ts_valid_until_ms);
CREATE INDEX partial_state_events_room_id_idx ON partial_state_events USING btree (room_id);
CREATE INDEX presence_stream_id ON presence_stream USING btree (stream_id, user_id);
CREATE INDEX presence_stream_state_not_offline_idx ON presence_stream USING btree (state) WHERE (state <> 'offline'::text);
CREATE INDEX presence_stream_user_id ON presence_stream USING btree (user_id);
CREATE INDEX public_room_index ON rooms USING btree (is_public);
CREATE INDEX push_rules_enable_user_name ON push_rules_enable USING btree (user_name);
CREATE INDEX push_rules_stream_id ON push_rules_stream USING btree (stream_id);
CREATE INDEX push_rules_stream_user_stream_id ON push_rules_stream USING btree (user_id, stream_id);
CREATE INDEX push_rules_user_name ON push_rules USING btree (user_name);
CREATE UNIQUE INDEX ratelimit_override_idx ON ratelimit_override USING btree (user_id);
CREATE UNIQUE INDEX receipts_graph_unique_index ON receipts_graph USING btree (room_id, receipt_type, user_id) WHERE (thread_id IS NULL);
CREATE INDEX receipts_linearized_id ON receipts_linearized USING btree (stream_id);
CREATE INDEX receipts_linearized_room_stream ON receipts_linearized USING btree (room_id, stream_id);
CREATE UNIQUE INDEX receipts_linearized_unique_index ON receipts_linearized USING btree (room_id, receipt_type, user_id) WHERE (thread_id IS NULL);
CREATE INDEX receipts_linearized_user ON receipts_linearized USING btree (user_id);
CREATE INDEX received_transactions_ts ON received_transactions USING btree (ts);
CREATE INDEX redactions_have_censored_ts ON redactions USING btree (received_ts) WHERE (NOT have_censored);
CREATE INDEX redactions_redacts ON redactions USING btree (redacts);
CREATE INDEX refresh_tokens_next_token_id ON refresh_tokens USING btree (next_token_id) WHERE (next_token_id IS NOT NULL);
CREATE UNIQUE INDEX remote_media_repository_thumbn_media_origin_id_width_height_met ON remote_media_cache_thumbnails USING btree (media_origin, media_id, thumbnail_width, thumbnail_height, thumbnail_type, thumbnail_method);
CREATE INDEX room_account_data_stream_id ON room_account_data USING btree (user_id, stream_id);
CREATE INDEX room_alias_servers_alias ON room_alias_servers USING btree (room_alias);
CREATE INDEX room_aliases_id ON room_aliases USING btree (room_id);
CREATE INDEX room_memberships_room_id ON room_memberships USING btree (room_id);
CREATE INDEX room_memberships_user_id ON room_memberships USING btree (user_id);
CREATE INDEX room_memberships_user_room_forgotten ON room_memberships USING btree (user_id, room_id) WHERE (forgotten = 1);
CREATE INDEX room_retention_max_lifetime_idx ON room_retention USING btree (max_lifetime);
CREATE UNIQUE INDEX room_stats_earliest_token_idx ON room_stats_earliest_token USING btree (room_id);
CREATE UNIQUE INDEX room_stats_state_room ON room_stats_state USING btree (room_id);
CREATE INDEX stream_ordering_to_exterm_idx ON stream_ordering_to_exterm USING btree (stream_ordering);
CREATE INDEX stream_ordering_to_exterm_rm_idx ON stream_ordering_to_exterm USING btree (room_id, stream_ordering);
CREATE UNIQUE INDEX stream_positions_idx ON stream_positions USING btree (stream_name, instance_name);
CREATE UNIQUE INDEX threepid_guest_access_tokens_index ON threepid_guest_access_tokens USING btree (medium, address);
CREATE INDEX threepid_validation_token_session_id ON threepid_validation_token USING btree (session_id);
CREATE INDEX user_daily_visits_ts_idx ON user_daily_visits USING btree ("timestamp");
CREATE INDEX user_daily_visits_uts_idx ON user_daily_visits USING btree (user_id, "timestamp");
CREATE INDEX user_directory_room_idx ON user_directory USING btree (room_id);
CREATE INDEX user_directory_search_fts_idx ON user_directory_search USING gin (vector);
CREATE UNIQUE INDEX user_directory_search_user_idx ON user_directory_search USING btree (user_id);
CREATE UNIQUE INDEX user_directory_user_idx ON user_directory USING btree (user_id);
CREATE INDEX user_external_ids_user_id_idx ON user_external_ids USING btree (user_id);
CREATE UNIQUE INDEX user_filters_unique ON user_filters USING btree (user_id, filter_id);
CREATE INDEX user_ips_device_id ON user_ips USING btree (user_id, device_id, last_seen);
CREATE INDEX user_ips_last_seen ON user_ips USING btree (user_id, last_seen);
CREATE INDEX user_ips_last_seen_only ON user_ips USING btree (last_seen);
CREATE UNIQUE INDEX user_ips_user_token_ip_unique_index ON user_ips USING btree (user_id, access_token, ip);
CREATE UNIQUE INDEX user_signature_stream_idx ON user_signature_stream USING btree (stream_id);
CREATE UNIQUE INDEX user_threepid_id_server_idx ON user_threepid_id_server USING btree (user_id, medium, address, id_server);
CREATE INDEX user_threepids_medium_address ON user_threepids USING btree (medium, address);
CREATE INDEX user_threepids_user_id ON user_threepids USING btree (user_id);
CREATE INDEX users_creation_ts ON users USING btree (creation_ts);
CREATE INDEX users_have_local_media ON local_media_repository USING btree (user_id, created_ts);
CREATE INDEX users_in_public_rooms_r_idx ON users_in_public_rooms USING btree (room_id);
CREATE UNIQUE INDEX users_in_public_rooms_u_idx ON users_in_public_rooms USING btree (user_id, room_id);
CREATE INDEX users_who_share_private_rooms_o_idx ON users_who_share_private_rooms USING btree (other_user_id);
CREATE INDEX users_who_share_private_rooms_r_idx ON users_who_share_private_rooms USING btree (room_id);
CREATE UNIQUE INDEX users_who_share_private_rooms_u_idx ON users_who_share_private_rooms USING btree (user_id, other_user_id, room_id);
CREATE UNIQUE INDEX worker_locks_key ON worker_locks USING btree (lock_name, lock_key);
CREATE TRIGGER check_partial_state_events BEFORE INSERT OR UPDATE ON partial_state_events FOR EACH ROW EXECUTE PROCEDURE check_partial_state_events();
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_refresh_token_id_fkey FOREIGN KEY (refresh_token_id) REFERENCES refresh_tokens(id) ON DELETE CASCADE;
ALTER TABLE ONLY destination_rooms
    ADD CONSTRAINT destination_rooms_destination_fkey FOREIGN KEY (destination) REFERENCES destinations(destination);
ALTER TABLE ONLY destination_rooms
    ADD CONSTRAINT destination_rooms_room_id_fkey FOREIGN KEY (room_id) REFERENCES rooms(room_id);
ALTER TABLE ONLY event_edges
    ADD CONSTRAINT event_edges_event_id_fkey FOREIGN KEY (event_id) REFERENCES events(event_id);
ALTER TABLE ONLY event_txn_id
    ADD CONSTRAINT event_txn_id_event_id_fkey FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE;
ALTER TABLE ONLY event_txn_id
    ADD CONSTRAINT event_txn_id_token_id_fkey FOREIGN KEY (token_id) REFERENCES access_tokens(id) ON DELETE CASCADE;
ALTER TABLE ONLY partial_state_events
    ADD CONSTRAINT partial_state_events_event_id_fkey FOREIGN KEY (event_id) REFERENCES events(event_id);
ALTER TABLE ONLY partial_state_events
    ADD CONSTRAINT partial_state_events_room_id_fkey FOREIGN KEY (room_id) REFERENCES partial_state_rooms(room_id);
ALTER TABLE ONLY partial_state_rooms
    ADD CONSTRAINT partial_state_rooms_room_id_fkey FOREIGN KEY (room_id) REFERENCES rooms(room_id);
ALTER TABLE ONLY partial_state_rooms_servers
    ADD CONSTRAINT partial_state_rooms_servers_room_id_fkey FOREIGN KEY (room_id) REFERENCES partial_state_rooms(room_id);
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_next_token_id_fkey FOREIGN KEY (next_token_id) REFERENCES refresh_tokens(id) ON DELETE CASCADE;
ALTER TABLE ONLY ui_auth_sessions_credentials
    ADD CONSTRAINT ui_auth_sessions_credentials_session_id_fkey FOREIGN KEY (session_id) REFERENCES ui_auth_sessions(session_id);
ALTER TABLE ONLY ui_auth_sessions_ips
    ADD CONSTRAINT ui_auth_sessions_ips_session_id_fkey FOREIGN KEY (session_id) REFERENCES ui_auth_sessions(session_id);
ALTER TABLE ONLY users_to_send_full_presence_to
    ADD CONSTRAINT users_to_send_full_presence_to_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(name);
INSERT INTO appservice_stream_position VALUES ('X', 0);
INSERT INTO event_push_summary_last_receipt_stream_id VALUES ('X', 0);
INSERT INTO event_push_summary_stream_ordering VALUES ('X', 0);
INSERT INTO federation_stream_position VALUES ('federation', -1, 'master');
INSERT INTO federation_stream_position VALUES ('events', -1, 'master');
INSERT INTO stats_incremental_position VALUES ('X', 1);
INSERT INTO user_directory_stream_pos VALUES ('X', 1);
SELECT pg_catalog.setval('account_data_sequence', 1, true);
SELECT pg_catalog.setval('application_services_txn_id_seq', 1, false);
SELECT pg_catalog.setval('cache_invalidation_stream_seq', 1, true);
SELECT pg_catalog.setval('device_inbox_sequence', 1, true);
SELECT pg_catalog.setval('event_auth_chain_id', 1, false);
SELECT pg_catalog.setval('events_backfill_stream_seq', 1, true);
SELECT pg_catalog.setval('events_stream_seq', 1, true);
SELECT pg_catalog.setval('instance_map_instance_id_seq', 1, false);
SELECT pg_catalog.setval('presence_stream_sequence', 1, true);
SELECT pg_catalog.setval('receipts_sequence', 1, true);
SELECT pg_catalog.setval('user_id_seq', 1, false);
