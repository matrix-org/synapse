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
from synapse.types import get_domain_from_id, UserID

from signedjson.sign import sign_json

import functools
import logging

logger = logging.getLogger(__name__)


# TODO: Renew assestations
# TODO: Validate assestations
# TODO: Allow remote servers to accept invitations to rooms asyncly.
# TODO: Allow users to "knock" or simpkly join depending on rules
# TODO: Federation admin APIs
# TODO: is_priveged flag to users and is_public to users and rooms
# TODO: Roles
# TODO: Group memebrship stream
# TODO: Self memebrship management
# TODO: Audit log for admins (profile updates, membership changes, users who tried
#       to join but were rejected, etc)
# TODO: Flairs


DEFAULT_ASSESSTATION_LENGTH_MS = 3 * 24 * 60 * 60 * 1000


def check_group_is_ours(and_exists=False):
    def g(func):
        @functools.wraps(func)
        @defer.inlineCallbacks
        def h(self, group_id, *args, **kwargs):
            if not self.is_mine_id(group_id):
                raise SynapseError(400, "Group not on this server")
            if and_exists:
                group = yield self.store.get_group(group_id)
                if not group:
                    raise SynapseError(404, "Unknown group")

            res = yield func(self, group_id, *args, **kwargs)
            defer.returnValue(res)

        return h
    return g


class GroupsServerHandler(object):
    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.room_list_handler = hs.get_room_list_handler()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.keyring = hs.get_keyring()
        self.is_mine_id = hs.is_mine_id
        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def get_group_summary(self, group_id, requester_user_id):
        profile = yield self.get_group_profile(group_id, requester_user_id)
        users = yield self.get_users_in_group(group_id, requester_user_id)
        rooms = yield self.get_rooms_in_group(group_id, requester_user_id)
        defer.returnValue({
            "profile": profile,
            "users": users,
            "rooms": rooms,
        })

    @check_group_is_ours()
    @defer.inlineCallbacks
    def get_group_profile(self, group_id, requester_user_id):
        group_description = yield self.store.get_group(group_id)

        if group_description:
            defer.returnValue(group_description)
        else:
            raise SynapseError(404, "Unknown group")

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def get_users_in_group(self, group_id, requester_user_id):
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

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def get_rooms_in_group(self, group_id, requester_user_id):
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

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def add_room(self, group_id, requester_user_id, room_id, content):
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

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def invite(self, group_id, user_id, requester_user_id, content, local_result=None):
        is_admin = yield self.store.is_user_admin_in_group(
            group_id, requester_user_id
        )
        if not is_admin:
            raise SynapseError(403, "User is not admin in group")

        # TODO: Check if user knocked
        # TODO: Check if user is already invited

        group = yield self.store.get_group(group_id)
        content = {
            "profile": {
                "name": group["name"],
                "avatar_url": group["avatar_url"],
            }
        }

        if self.hs.is_mine_id(user_id):
            groups_local = self.hs.get_groups_local_handler()
            res = yield groups_local.on_invite(group_id, user_id, content)
        else:
            domain = get_domain_from_id(user_id)

            content.update({
                "assestation": self._create_assestation(group_id, user_id),
            })

            repl_layer = self.hs.get_replication_layer()
            res = yield repl_layer.send_group_user_join(group_id, user_id, content)

        if res["state"] == "join":
            if not self.hs.is_mine_id(user_id):
                assestation = res["assestation"]
                valid_until_ms = assestation["valid_until_ms"]
                # TODO: Check valid_until_ms > now

                yield self.keyring.verify_json_for_server(domain, assestation)
            else:
                assestation = None
                valid_until_ms = None

            yield self.store.add_user_to_group(
                group_id, user_id,
                is_admin=False,
                is_public=False,  # TODO
                assestation=assestation,
                valid_until_ms=valid_until_ms,
            )
        elif res["state"] == "invite":
            yield self.store.add_group_invite(
                group_id, user_id,
            )
            defer.returnValue({
                "state": "invite"
            })
        elif res["state"] == "reject":
            defer.returnValue({
                "state": "reject"
            })
        else:
            raise SynapseError(502, "Unknown state returned by HS")

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def accept_invite(self, group_id, user_id, content):
        if not self.store.is_user_invited_to_local_group(group_id, user_id):
            raise SynapseError(403, "User not invited to group")

        if not self.hs.is_mine_id(user_id):
            assestation = content["assestation"]
            valid_until_ms = assestation["valid_until_ms"]
            # TODO: Check valid_until_ms > now

            domain = get_domain_from_id(user_id)
            yield self.keyring.verify_json_for_server(domain, assestation)
        else:
            assestation = None
            valid_until_ms = None

        yield self.store.add_user_to_group(
            group_id, user_id,
            is_admin=False,
            is_public=False,  # TODO
            assestation=assestation,
            valid_until_ms=valid_until_ms,
        )

        defer.returnValue({
            "state": "join",
            "assestation": self._create_assestation(group_id, user_id),
        })

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def knock(self, group_id, user_id, content):
        pass

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def accept_knock(self, group_id, user_id, content):
        pass

    @check_group_is_ours(and_exists=True)
    @defer.inlineCallbacks
    def remove_from_group(self, group_id, user_id, requester_user_id, content):
        is_kick = False
        if requester_user_id != user_id:
            is_admin = yield self.store.is_user_admin_in_group(
                group_id, requester_user_id
            )
            if not is_admin:
                raise SynapseError(403, "User is not admin in group")

            is_kick = True

        yield self.store.remove_user_to_group(
            group_id, user_id,
        )

        if is_kick:
            if self.hs.is_mine_id(user_id):
                groups_local = self.hs.get_groups_local_handler()
                yield groups_local.user_removed_from_group(group_id, user_id, {})
            else:
                # TODO: Send leave notification over federation
                pass

        defer.returnValue({})

    @check_group_is_ours()
    @defer.inlineCallbacks
    def create_group(self, group_id, user_id, content):
        logger.info("Attempting to create group with ID: %r", group_id)
        group = yield self.store.get_group(group_id)
        if group:
            raise SynapseError(400, "Group already exists")

        is_admin = yield self.auth.is_server_admin(UserID.from_string(user_id))
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

        if not self.hs.is_mine_id(user_id):
            assestation = content["assestation"]
            valid_until_ms = assestation["valid_until_ms"]
            # TODO: Check valid_until_ms > now

            domain = get_domain_from_id(user_id)
            yield self.keyring.verify_json_for_server(domain, assestation)
        else:
            assestation = None
            valid_until_ms = None

        yield self.store.add_user_to_group(
            group_id, user_id,
            is_admin=True,
            is_public=True,  # TODO
            assestation=assestation,
            valid_until_ms=valid_until_ms,
        )

        defer.returnValue({"group_id": group_id})

    def _create_assestation(self, group_id, user_id):
        return sign_json({
            "group_id": group_id,
            "user_id": user_id,
            "valid_until_ms": self.clock.time_msec() + DEFAULT_ASSESSTATION_LENGTH_MS,
        }, self.server_name, self.signing_key)
