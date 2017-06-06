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
        self.auth = hs.get_auth()
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

    @defer.inlineCallbacks
    def create_group(self, group_id, requester, content):
        logger.info("Attempting to create group with ID: %r", group_id)
        group = yield self.store.get_group(group_id)
        if group:
            raise SynapseError(400, "Group already exists")

        user_id = requester.user.to_string()

        if not self.is_mine_id(group_id):
            repl_layer = self.hs.get_replication_layer()
            res = yield repl_layer.create_group(group_id, user_id)  # TODO
            defer.returnValue(res)

        is_admin = yield self.auth.is_server_admin(requester.user)
        if not is_admin and not group_id.startswith("+u/"):
            raise SynapseError(403, "Group ID must start with '+u/' or be a server admin")

        profile = content.get("profile", {})
        name = profile.get("name")
        avatar_url = profile.get("avatar_url")
        short_description = profile.get("short_description")
        long_description = profile.get("long_description")

        yield self.store.create_group(
            group_id,
            user_id,
            name=name,
            avatar_url=avatar_url,
            short_description=short_description,
            long_description=long_description,
        )

        yield self._change_user_memebrship(
            group_id, user_id,
            membership="join",
            is_admin=True,
            is_public=True,
        )

        defer.returnValue({"group_id": group_id})

    @defer.inlineCallbacks
    def add_room(self, group_id, requester_user_id, room_id, content):
        # TODO: Remote

        group = yield self.store.get_group(group_id)
        if not group:
            raise SynapseError(404, "Unknown group")

        is_admin = yield self.store.is_user_admin_in_group(group_id, requester_user_id)
        if not is_admin:
            raise SynapseError(403, "User is not admin in group")

        # TODO: Check if room has already been added

        visibility = content.get("visibility")
        if visibility:
            vis_type = visibility["type"]
            if vis_type not in ("public", "private"):
                raise SynapseError(
                    400, "Synapse only supports 'public'/'private' visibility"
                )
            is_public = vis_type == "public"
        else:
            is_public = True

        yield self.store.add_room_to_group(group_id, room_id, is_public=is_public)

        defer.returnValue({})

    @defer.inlineCallbacks
    def add_user(self, group_id, requester_user_id, target_user_id, content):
        # TODO: Remote

        group = yield self.store.get_group(group_id)
        if not group:
            raise SynapseError(404, "Unknown group")

        is_admin = yield self.store.is_user_admin_in_group(group_id, requester_user_id)
        if not is_admin:
            raise SynapseError(403, "User is not admin in group")

        # TODO: Check if user has already been added

        visibility = content.get("visibility")
        if visibility:
            vis_type = visibility["type"]
            if vis_type not in ("public", "private"):
                raise SynapseError(
                    400, "Synapse only supports 'public'/'private' visibility"
                )
            is_public = vis_type == "public"
        else:
            is_public = True

        yield self._change_user_memebrship(
            group_id, target_user_id,
            membership="join",
            is_admin=False,
            is_public=is_public,
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def _change_user_memebrship(self, group_id, user_id, membership, is_admin=False,
                                is_public=True):
        yield self.store.add_user_to_group(
            group_id, user_id, is_admin=is_admin, is_public=is_public,
        )
        if self.hs.is_mine_id(user_id):
            yield self.store.register_user_group_membership(
                group_id, user_id, is_admin=is_admin, membership=membership,
            )
        else:
            repl_layer = self.hs.get_replication_layer()
            yield repl_layer.send_group_user_membership(group_id, user_id, {
                "membership": membership,
            })

    def on_groups_users_membership(self, group_id, user_states):
        for user_id, user_state in user_states.iteritems():
            membership = user_state["membership"]
            is_admin = user_state["is_admin"]
            if not self.is_mine_id(user_id):
                logger.warn(
                    "Group %r informed us of %r of user %r",
                    group_id, membership, user_id
                )
                continue
            if membership not in ("join", "leave",):
                logger.warn(
                    "Group %r informed us of unkown membership state %r for user %r",
                    group_id, membership, user_id
                )
                continue
            yield self.store.register_user_group_membership(
                group_id, user_id, is_admin, membership
            )

    def on_groups_users_admin_join_user(self, group_id, requester_user_id, content):
        group = yield self.store.get_group(group_id)
        if not group:
            raise SynapseError(404, "Unknown group")

        is_admin = yield self.store.is_user_admin_in_group(group_id, requester_user_id)
        if not is_admin:
            raise SynapseError(403, "User is not admin in group")

        user_id = content["target_user_id"]
        membership = content["membership"]

        if membership not in ("join", "leave",):
            logger.warn(
                "Group %r informed us of unkown membership state %r for user %r",
                group_id, membership, user_id
            )
            raise SynapseError(400, "Unknown membership %r" % (membership,))

        if membership == "join":
            yield self.store.add_user_to_group(group_id, user_id)
        else:
            yield self.store.remove_user_to_group(group_id, user_id)

        if self.hs.is_mine_id(user_id):
            yield self.store.register_user_group_membership(
                group_id, user_id, is_admin=False, membership=membership,
            )
        else:
            repl_layer = self.hs.get_replication_layer()
            yield repl_layer.send_group_user_membership(group_id, user_id, {
                "membership": membership,
            })
