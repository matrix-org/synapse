# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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

from twisted.internet import defer

from ._base import BaseHandler

from synapse.api.constants import (
    EventTypes, JoinRules,
)
from synapse.api.errors import SynapseError
from synapse.util.async import concurrently_execute
from synapse.util.caches.response_cache import ResponseCache

from collections import namedtuple
from unpaddedbase64 import encode_base64, decode_base64

import logging
import msgpack

logger = logging.getLogger(__name__)

REMOTE_ROOM_LIST_POLL_INTERVAL = 60 * 1000


class RoomListHandler(BaseHandler):
    def __init__(self, hs):
        super(RoomListHandler, self).__init__(hs)
        self.response_cache = ResponseCache(hs)

    def get_local_public_room_list(self, limit=None, next_batch=None):
        result = self.response_cache.get((limit, next_batch))
        if not result:
            result = self.response_cache.set(
                (limit, next_batch),
                self._get_public_room_list(limit, next_batch)
            )
        return result

    @defer.inlineCallbacks
    def _get_public_room_list(self, limit=None, next_batch=None):
        if next_batch and next_batch != "END":
            next_batch = RoomListNextBatch.from_token(next_batch)
        else:
            next_batch = None

        room_ids = yield self.store.get_public_room_ids()

        rooms_to_order_value = {}
        rooms_to_num_joined = {}
        rooms_to_latest_event_ids = {}

        if next_batch:
            current_stream_token = next_batch.sstream_ordering
        else:
            current_stream_token = yield self.store.get_room_max_stream_ordering()

        # We want to return rooms in a particular order: the number of joined
        # users. We then arbitrarily use the room_id as a tie breaker.

        @defer.inlineCallbacks
        def get_order_for_room(room_id):
            latest_event_ids = rooms_to_latest_event_ids.get(room_id, None)
            if not latest_event_ids:
                latest_event_ids = yield self.store.get_forward_extremeties_for_room(
                    room_id, current_stream_token
                )
                rooms_to_latest_event_ids[room_id] = latest_event_ids

            if not latest_event_ids:
                return

            joined_users = yield self.state_handler.get_current_user_in_room(
                room_id, latest_event_ids,
            )
            num_joined_users = len(joined_users)
            rooms_to_num_joined[room_id] = num_joined_users

            if num_joined_users == 0:
                return

            # We want larger rooms to be first, hence negating num_joined_users
            rooms_to_order_value[room_id] = (-num_joined_users, room_id)

        yield concurrently_execute(get_order_for_room, room_ids, 10)

        sorted_entries = sorted(rooms_to_order_value.items(), key=lambda e: e[1])
        sorted_rooms = [room_id for room_id, _ in sorted_entries]

        if next_batch:
            sorted_rooms = sorted_rooms[next_batch.current_limit:]

        new_limit = None
        if limit:
            if sorted_rooms[limit:]:
                new_limit = limit
                if next_batch:
                    new_limit += next_batch.current_limit
            sorted_rooms = sorted_rooms[:limit]

        results = []

        @defer.inlineCallbacks
        def handle_room(room_id):
            num_joined_users = rooms_to_num_joined[room_id]
            if num_joined_users == 0:
                return

            result = {
                "room_id": room_id,
                "num_joined_members": num_joined_users,
            }

            current_state_ids = yield self.state_handler.get_current_state_ids(room_id)

            event_map = yield self.store.get_events([
                event_id for key, event_id in current_state_ids.items()
                if key[0] in (
                    EventTypes.JoinRules,
                    EventTypes.Name,
                    EventTypes.Topic,
                    EventTypes.CanonicalAlias,
                    EventTypes.RoomHistoryVisibility,
                    EventTypes.GuestAccess,
                    "m.room.avatar",
                )
            ])

            current_state = {
                (ev.type, ev.state_key): ev
                for ev in event_map.values()
            }

            # Double check that this is actually a public room.
            join_rules_event = current_state.get((EventTypes.JoinRules, ""))
            if join_rules_event:
                join_rule = join_rules_event.content.get("join_rule", None)
                if join_rule and join_rule != JoinRules.PUBLIC:
                    defer.returnValue(None)

            aliases = yield self.store.get_aliases_for_room(room_id)
            if aliases:
                result["aliases"] = aliases

            name_event = yield current_state.get((EventTypes.Name, ""))
            if name_event:
                name = name_event.content.get("name", None)
                if name:
                    result["name"] = name

            topic_event = current_state.get((EventTypes.Topic, ""))
            if topic_event:
                topic = topic_event.content.get("topic", None)
                if topic:
                    result["topic"] = topic

            canonical_event = current_state.get((EventTypes.CanonicalAlias, ""))
            if canonical_event:
                canonical_alias = canonical_event.content.get("alias", None)
                if canonical_alias:
                    result["canonical_alias"] = canonical_alias

            visibility_event = current_state.get((EventTypes.RoomHistoryVisibility, ""))
            visibility = None
            if visibility_event:
                visibility = visibility_event.content.get("history_visibility", None)
            result["world_readable"] = visibility == "world_readable"

            guest_event = current_state.get((EventTypes.GuestAccess, ""))
            guest = None
            if guest_event:
                guest = guest_event.content.get("guest_access", None)
            result["guest_can_join"] = guest == "can_join"

            avatar_event = current_state.get(("m.room.avatar", ""))
            if avatar_event:
                avatar_url = avatar_event.content.get("url", None)
                if avatar_url:
                    result["avatar_url"] = avatar_url

            results.append(result)

        yield concurrently_execute(handle_room, sorted_rooms, 10)

        if new_limit:
            end_token = RoomListNextBatch(
                stream_ordering=current_stream_token,
                current_limit=new_limit,
            ).to_token()
        else:
            end_token = "END"

        if next_batch:
            start_token = next_batch.to_token()
        else:
            start_token = "START"

        defer.returnValue({
            "start": start_token,
            "end": end_token,
            "chunk": results,
        })

    @defer.inlineCallbacks
    def get_remote_public_room_list(self, server_name):
        res = yield self.hs.get_replication_layer().get_public_rooms(
            [server_name]
        )

        if server_name not in res:
            raise SynapseError(404, "Server not found")
        defer.returnValue(res[server_name])


class RoomListNextBatch(namedtuple("RoomListNextBatch", (
    "stream_ordering",  # stream_ordering of the first public room list
    "current_limit",  # The number of previous rooms returned
))):

    KEY_DICT = {
        "stream_ordering": "s",
        "current_limit": "n",
    }

    REVERSE_KEY_DICT = {v: k for k, v in KEY_DICT.items()}

    @classmethod
    def from_token(cls, token):
        return RoomListNextBatch(**{
            cls.REVERSE_KEY_DICT[key]: val
            for key, val in msgpack.loads(decode_base64(token)).items()
        })

    def to_token(self):
        return encode_base64(msgpack.dumps({
            self.KEY_DICT[key]: val
            for key, val in self._asdict().items()
        }))
