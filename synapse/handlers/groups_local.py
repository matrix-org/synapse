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
from synapse.types import get_domain_from_id

from signedjson.sign import sign_json

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


class GroupsLocalHandler(object):
    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.room_list_handler = hs.get_room_list_handler()
        self.groups_server_handler = hs.get_groups_server_handler()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.keyring = hs.get_keyring()
        self.is_mine_id = hs.is_mine_id
        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname

    def get_group_summary(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.groups_server_handler.get_group_summary(
                group_id, requester_user_id
            )

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_group_summary(group_id, requester_user_id)

    def get_group_profile(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.groups_server_handler.get_group_profile(
                group_id, requester_user_id
            )

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_group_profile(group_id, requester_user_id)

    def get_users_in_group(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.groups_server_handler.get_users_in_group(
                group_id, requester_user_id
            )

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_group_users(group_id, requester_user_id)

    def get_rooms_in_group(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            return self.groups_server_handler.get_rooms_in_group(
                group_id, requester_user_id
            )

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.get_group_rooms(group_id, requester_user_id)

    def create_group(self, group_id, user_id, content):
        logger.info("Asking to create group with ID: %r", group_id)

        if self.is_mine_id(group_id):
            return self.groups_server_handler.create_group(
                group_id, user_id, content
            )

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.create_group(group_id, user_id, content)  # TODO

    def add_room(self, group_id, user_id, room_id, content):
        if self.is_mine_id(group_id):
            return self.groups_server_handler.add_room(
                group_id, user_id, room_id, content
            )

        repl_layer = self.hs.get_replication_layer()
        return repl_layer.add_room_to_group(group_id, user_id, room_id, content)  # TODO

    @defer.inlineCallbacks
    def accept_invite(self, group_id, user_id, content):
        if self.is_mine_id(group_id):
            yield self.groups_server_handler.accept_invite(
                group_id, user_id, content
            )
            assestation = None
            valid_until_ms = None
        else:
            repl_layer = self.hs.get_replication_layer()
            res = yield repl_layer.accept_invite(group_id, user_id, content)  # TODO
            assestation = res["assestation"]
            valid_until_ms = assestation["valid_until_ms"]
            # TODO: Check valid_until_ms > now

            domain = get_domain_from_id(user_id)
            yield self.keyring.verify_json_for_server(domain, assestation)

        yield self.store.register_user_group_membership(
            group_id, user_id,
            membership="join",
            is_admin=False,
            assestation=assestation,
            valid_until_ms=valid_until_ms,
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def invite(self, group_id, user_id, requester_user_id, content):
        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.invite(
                group_id, user_id, requester_user_id, content,
                local_result={"state": "invite"}
            )
        else:
            repl_layer = self.hs.get_replication_layer()
            res = yield repl_layer.invite_to_group(
                group_id, user_id, requester_user_id, content
            )  # TODO

        if res["state"] == "join":
            if not self.hs.is_mine_id(group_id):
                assestation = res["assestation"]
                valid_until_ms = assestation["valid_until_ms"]
                # TODO: Check valid_until_ms > now

                domain = get_domain_from_id(group_id)
                yield self.keyring.verify_json_for_server(domain, assestation)
            else:
                assestation = None
                valid_until_ms = None

            yield self.store.register_user_group_membership(
                group_id, user_id,
                membership="join",
                assestation=assestation,
                valid_until_ms=valid_until_ms,
            )
        elif res["state"] == "invite":
            yield self.store.register_user_group_membership(
                group_id, user_id,
                membership="invite",
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

    def _create_assestation(self, group_id, user_id):
        return sign_json({
            "group_id": group_id,
            "user_id": user_id,
            "valid_until_ms": self.clock.time_msec() + DEFAULT_ASSESSTATION_LENGTH_MS,
        }, self.server_name, self.signing_key)

    @defer.inlineCallbacks
    def get_joined_groups(self, user_id):
        group_ids = yield self.store.get_joined_groups(user_id)
        defer.returnValue({"groups": group_ids})
