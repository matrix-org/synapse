# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from ._base import BaseSlavedStore
from ._slaved_id_tracker import SlavedIdTracker

from synapse.api.constants import EventTypes
from synapse.storage import DataStore
from synapse.storage.roommember import RoomMemberStore
from synapse.storage.event_federation import EventFederationStore
from synapse.storage.event_push_actions import EventPushActionsStore
from synapse.storage.state import StateStore
from synapse.storage.stream import StreamStore
from synapse.util.caches.stream_change_cache import StreamChangeCache

import logging


logger = logging.getLogger(__name__)


# So, um, we want to borrow a load of functions intended for reading from
# a DataStore, but we don't want to take functions that either write to the
# DataStore or are cached and don't have cache invalidation logic.
#
# Rather than write duplicate versions of those functions, or lift them to
# a common base class, we going to grab the underlying __func__ object from
# the method descriptor on the DataStore and chuck them into our class.


class SlavedEventStore(BaseSlavedStore):

    def __init__(self, db_conn, hs):
        super(SlavedEventStore, self).__init__(db_conn, hs)
        self._stream_id_gen = SlavedIdTracker(
            db_conn, "events", "stream_ordering",
        )
        self._backfill_id_gen = SlavedIdTracker(
            db_conn, "events", "stream_ordering", step=-1
        )
        events_max = self._stream_id_gen.get_current_token()
        event_cache_prefill, min_event_val = self._get_cache_dict(
            db_conn, "events",
            entity_column="room_id",
            stream_column="stream_ordering",
            max_value=events_max,
        )
        self._events_stream_cache = StreamChangeCache(
            "EventsRoomStreamChangeCache", min_event_val,
            prefilled_cache=event_cache_prefill,
        )
        self._membership_stream_cache = StreamChangeCache(
            "MembershipStreamChangeCache", events_max,
        )

        self.stream_ordering_month_ago = 0
        self._stream_order_on_start = self.get_room_max_stream_ordering()

    # Cached functions can't be accessed through a class instance so we need
    # to reach inside the __dict__ to extract them.
    get_rooms_for_user = RoomMemberStore.__dict__["get_rooms_for_user"]
    get_users_in_room = RoomMemberStore.__dict__["get_users_in_room"]
    get_hosts_in_room = RoomMemberStore.__dict__["get_hosts_in_room"]
    get_users_who_share_room_with_user = (
        RoomMemberStore.__dict__["get_users_who_share_room_with_user"]
    )
    get_latest_event_ids_in_room = EventFederationStore.__dict__[
        "get_latest_event_ids_in_room"
    ]
    get_invited_rooms_for_user = RoomMemberStore.__dict__[
        "get_invited_rooms_for_user"
    ]
    get_unread_event_push_actions_by_room_for_user = (
        EventPushActionsStore.__dict__["get_unread_event_push_actions_by_room_for_user"]
    )
    _get_unread_counts_by_receipt_txn = (
        DataStore._get_unread_counts_by_receipt_txn.__func__
    )
    _get_unread_counts_by_pos_txn = (
        DataStore._get_unread_counts_by_pos_txn.__func__
    )
    _get_state_group_for_events = (
        StateStore.__dict__["_get_state_group_for_events"]
    )
    _get_state_group_for_event = (
        StateStore.__dict__["_get_state_group_for_event"]
    )
    _get_state_groups_from_groups = (
        StateStore.__dict__["_get_state_groups_from_groups"]
    )
    _get_state_groups_from_groups_txn = (
        DataStore._get_state_groups_from_groups_txn.__func__
    )
    get_recent_event_ids_for_room = (
        StreamStore.__dict__["get_recent_event_ids_for_room"]
    )
    get_current_state_ids = (
        StateStore.__dict__["get_current_state_ids"]
    )
    get_state_group_delta = StateStore.__dict__["get_state_group_delta"]
    _get_joined_hosts_cache = RoomMemberStore.__dict__["_get_joined_hosts_cache"]
    has_room_changed_since = DataStore.has_room_changed_since.__func__

    get_unread_push_actions_for_user_in_range_for_http = (
        DataStore.get_unread_push_actions_for_user_in_range_for_http.__func__
    )
    get_unread_push_actions_for_user_in_range_for_email = (
        DataStore.get_unread_push_actions_for_user_in_range_for_email.__func__
    )
    get_push_action_users_in_range = (
        DataStore.get_push_action_users_in_range.__func__
    )
    get_event = DataStore.get_event.__func__
    get_events = DataStore.get_events.__func__
    get_rooms_for_user_where_membership_is = (
        DataStore.get_rooms_for_user_where_membership_is.__func__
    )
    get_membership_changes_for_user = (
        DataStore.get_membership_changes_for_user.__func__
    )
    get_room_events_max_id = DataStore.get_room_events_max_id.__func__
    get_room_events_stream_for_room = (
        DataStore.get_room_events_stream_for_room.__func__
    )
    get_events_around = DataStore.get_events_around.__func__
    get_state_for_event = DataStore.get_state_for_event.__func__
    get_state_for_events = DataStore.get_state_for_events.__func__
    get_state_groups = DataStore.get_state_groups.__func__
    get_state_groups_ids = DataStore.get_state_groups_ids.__func__
    get_state_ids_for_event = DataStore.get_state_ids_for_event.__func__
    get_state_ids_for_events = DataStore.get_state_ids_for_events.__func__
    get_joined_users_from_state = DataStore.get_joined_users_from_state.__func__
    get_joined_users_from_context = DataStore.get_joined_users_from_context.__func__
    _get_joined_users_from_context = (
        RoomMemberStore.__dict__["_get_joined_users_from_context"]
    )

    get_joined_hosts = DataStore.get_joined_hosts.__func__
    _get_joined_hosts = RoomMemberStore.__dict__["_get_joined_hosts"]

    get_recent_events_for_room = DataStore.get_recent_events_for_room.__func__
    get_room_events_stream_for_rooms = (
        DataStore.get_room_events_stream_for_rooms.__func__
    )
    is_host_joined = RoomMemberStore.__dict__["is_host_joined"]
    get_stream_token_for_event = DataStore.get_stream_token_for_event.__func__

    _set_before_and_after = staticmethod(DataStore._set_before_and_after)

    _get_events = DataStore._get_events.__func__
    _get_events_from_cache = DataStore._get_events_from_cache.__func__

    _invalidate_get_event_cache = DataStore._invalidate_get_event_cache.__func__
    _enqueue_events = DataStore._enqueue_events.__func__
    _do_fetch = DataStore._do_fetch.__func__
    _fetch_event_rows = DataStore._fetch_event_rows.__func__
    _get_event_from_row = DataStore._get_event_from_row.__func__
    _get_rooms_for_user_where_membership_is_txn = (
        DataStore._get_rooms_for_user_where_membership_is_txn.__func__
    )
    _get_state_for_groups = DataStore._get_state_for_groups.__func__
    _get_all_state_from_cache = DataStore._get_all_state_from_cache.__func__
    _get_events_around_txn = DataStore._get_events_around_txn.__func__
    _get_some_state_from_cache = DataStore._get_some_state_from_cache.__func__

    get_backfill_events = DataStore.get_backfill_events.__func__
    _get_backfill_events = DataStore._get_backfill_events.__func__
    get_missing_events = DataStore.get_missing_events.__func__
    _get_missing_events = DataStore._get_missing_events.__func__

    get_auth_chain = DataStore.get_auth_chain.__func__
    get_auth_chain_ids = DataStore.get_auth_chain_ids.__func__
    _get_auth_chain_ids_txn = DataStore._get_auth_chain_ids_txn.__func__

    get_room_max_stream_ordering = DataStore.get_room_max_stream_ordering.__func__

    get_forward_extremeties_for_room = (
        DataStore.get_forward_extremeties_for_room.__func__
    )
    _get_forward_extremeties_for_room = (
        EventFederationStore.__dict__["_get_forward_extremeties_for_room"]
    )

    get_all_new_events_stream = DataStore.get_all_new_events_stream.__func__

    get_federation_out_pos = DataStore.get_federation_out_pos.__func__
    update_federation_out_pos = DataStore.update_federation_out_pos.__func__

    def stream_positions(self):
        result = super(SlavedEventStore, self).stream_positions()
        result["events"] = self._stream_id_gen.get_current_token()
        result["backfill"] = -self._backfill_id_gen.get_current_token()
        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "events":
            self._stream_id_gen.advance(token)
            for row in rows:
                self.invalidate_caches_for_event(
                    token, row.event_id, row.room_id, row.type, row.state_key,
                    row.redacts,
                    backfilled=False,
                )
        elif stream_name == "backfill":
            self._backfill_id_gen.advance(-token)
            for row in rows:
                self.invalidate_caches_for_event(
                    -token, row.event_id, row.room_id, row.type, row.state_key,
                    row.redacts,
                    backfilled=True,
                )
        return super(SlavedEventStore, self).process_replication_rows(
            stream_name, token, rows
        )

    def invalidate_caches_for_event(self, stream_ordering, event_id, room_id,
                                    etype, state_key, redacts, backfilled):
        self._invalidate_get_event_cache(event_id)

        self.get_latest_event_ids_in_room.invalidate((room_id,))

        self.get_unread_event_push_actions_by_room_for_user.invalidate_many(
            (room_id,)
        )

        if not backfilled:
            self._events_stream_cache.entity_has_changed(
                room_id, stream_ordering
            )

        if redacts:
            self._invalidate_get_event_cache(redacts)

        if etype == EventTypes.Member:
            self._membership_stream_cache.entity_has_changed(
                state_key, stream_ordering
            )
            self.get_invited_rooms_for_user.invalidate((state_key,))
