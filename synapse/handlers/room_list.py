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
    EventTypes, JoinRules, Membership,
)
from synapse.api.errors import SynapseError
from synapse.util.async import concurrently_execute
from synapse.util.caches.response_cache import ResponseCache

import logging

logger = logging.getLogger(__name__)

REMOTE_ROOM_LIST_POLL_INTERVAL = 60 * 1000


class RoomListHandler(BaseHandler):
    def __init__(self, hs):
        super(RoomListHandler, self).__init__(hs)
        self.response_cache = ResponseCache(hs)
        self.remote_list_request_cache = ResponseCache(hs)
        self.remote_list_cache = {}
        self.fetch_looping_call = hs.get_clock().looping_call(
            self.fetch_all_remote_lists, REMOTE_ROOM_LIST_POLL_INTERVAL
        )
        self.fetch_all_remote_lists()

    def get_local_public_room_list(self):
        result = self.response_cache.get(())
        if not result:
            result = self.response_cache.set((), self._get_public_room_list())
        return result

    @defer.inlineCallbacks
    def _get_public_room_list(self):
        room_ids = yield self.store.get_public_room_ids()

        results = []

        @defer.inlineCallbacks
        def handle_room(room_id):
            current_state = yield self.state_handler.get_current_state(room_id)

            # Double check that this is actually a public room.
            join_rules_event = current_state.get((EventTypes.JoinRules, ""))
            if join_rules_event:
                join_rule = join_rules_event.content.get("join_rule", None)
                if join_rule and join_rule != JoinRules.PUBLIC:
                    defer.returnValue(None)

            result = {"room_id": room_id}

            num_joined_users = len([
                1 for _, event in current_state.items()
                if event.type == EventTypes.Member
                and event.membership == Membership.JOIN
            ])
            if num_joined_users == 0:
                return

            result["num_joined_members"] = num_joined_users

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

        yield concurrently_execute(handle_room, room_ids, 10)

        # FIXME (erikj): START is no longer a valid value
        defer.returnValue({"start": "START", "end": "END", "chunk": results})

    @defer.inlineCallbacks
    def fetch_all_remote_lists(self):
        deferred = self.hs.get_replication_layer().get_public_rooms(
            self.hs.config.secondary_directory_servers
        )
        self.remote_list_request_cache.set((), deferred)
        self.remote_list_cache = yield deferred

    @defer.inlineCallbacks
    def get_remote_public_room_list(self, server_name):
        res = yield self.hs.get_replication_layer().get_public_rooms(
            [server_name]
        )

        if server_name not in res:
            raise SynapseError(404, "Server not found")
        defer.returnValue(res[server_name])

    @defer.inlineCallbacks
    def get_aggregated_public_room_list(self):
        """
        Get the public room list from this server and the servers
        specified in the secondary_directory_servers config option.
        XXX: Pagination...
        """
        # We return the results from out cache which is updated by a looping call,
        # unless we're missing a cache entry, in which case wait for the result
        # of the fetch if there's one in progress. If not, omit that server.
        wait = False
        for s in self.hs.config.secondary_directory_servers:
            if s not in self.remote_list_cache:
                logger.warn("No cached room list from %s: waiting for fetch", s)
                wait = True
                break

        if wait and self.remote_list_request_cache.get(()):
            yield self.remote_list_request_cache.get(())

        public_rooms = yield self.get_local_public_room_list()

        # keep track of which room IDs we've seen so we can de-dup
        room_ids = set()

        # tag all the ones in our list with our server name.
        # Also add the them to the de-deping set
        for room in public_rooms['chunk']:
            room["server_name"] = self.hs.hostname
            room_ids.add(room["room_id"])

        # Now add the results from federation
        for server_name, server_result in self.remote_list_cache.items():
            for room in server_result["chunk"]:
                if room["room_id"] not in room_ids:
                    room["server_name"] = server_name
                    public_rooms["chunk"].append(room)
                    room_ids.add(room["room_id"])

        defer.returnValue(public_rooms)
