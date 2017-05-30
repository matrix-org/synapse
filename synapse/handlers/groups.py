# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

from synapse.api.errors import SynapseError

import logging

logger = logging.getLogger(__name__)


class GroupsHandler(object):
    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.room_list_handler = hs.get_room_list_handler()
        self.is_mine_id = hs.is_mine_id

    def get_group_summary(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.get_local_group_summary(group_id, requester_user_id)

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_group_summary(group_id, requester_user_id)

    @defer.inlineCallbacks
    def get_local_group_summary(self, group_id, requester_user_id):
        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Group not on this server")

        profile = yield self.get_local_group_profile(group_id, requester_user_id)
        users = yield self.get_local_users_in_group(group_id, requester_user_id)
        rooms = yield self.get_local_rooms_in_group(group_id, requester_user_id)
        defer.returnValue({
            "profile": profile,
            "users": users,
            "rooms": rooms,
        })

    def get_group_profile(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.get_local_group_profile(group_id, requester_user_id)

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_group_profile(group_id, requester_user_id)

    @defer.inlineCallbacks
    def get_local_group_profile(self, group_id, requester_user_id):
        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Group not on this server")

        group_description = yield self.store.get_group(group_id)

        if group_description:
            defer.returnValue(group_description)
        else:
            raise SynapseError(404, "Unknown group")

    def get_users_in_group(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.get_local_users_in_group(group_id, requester_user_id)

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_users_in_group(group_id, requester_user_id)

    def get_rooms_in_group(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.get_local_rooms_in_group(group_id, requester_user_id)

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_rooms_in_group(group_id, requester_user_id)

    @defer.inlineCallbacks
    def get_local_users_in_group(self, group_id, requester_user_id):
        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Group not on this server")

        group = yield self.store.get_group(group_id)
        if not group:
            raise SynapseError(404, "Unknown group")

        is_user_in_group = yield self.store.is_user_in_group(requester_user_id, group_id)

        user_results = yield self.store.get_users_in_group(
            group_id, include_private=is_user_in_group,
        )

        chunk = []
        for user_result in user_results:
            g_user_id = user_result["user_id"]
            is_public = user_result["is_public"]

            entry = {"user_id": g_user_id}

            # TODO: Get profile information

            if not is_public:
                entry["is_public"] = False

            chunk.append(entry)

        defer.returnValue({
            "chunk": chunk,
            "total_user_count_estimate": len(user_results),
        })

    @defer.inlineCallbacks
    def get_local_rooms_in_group(self, group_id, requester_user_id):
        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Group not on this server")

        group = yield self.store.get_group(group_id)
        if not group:
            raise SynapseError(404, "Unknown group")

        is_user_in_group = yield self.store.is_user_in_group(requester_user_id, group_id)

        room_results = yield self.store.get_rooms_in_group(
            group_id, include_private=is_user_in_group,
        )

        chunk = []
        for room_result in room_results:
            room_id = room_result["room_id"]
            is_public = room_result["is_public"]

            joined_users = yield self.store.get_users_in_room(room_id)
            entry = yield self.room_list_handler.generate_room_entry(
                room_id, len(joined_users),
                with_alias=False,
            )

            if not is_public:
                entry["is_public"] = False

            chunk.append(entry)

        chunk.sort(key=lambda e: -e["num_joined_members"])

        defer.returnValue({
            "chunk": chunk,
            "total_room_count_estimate": len(room_results),
        })
