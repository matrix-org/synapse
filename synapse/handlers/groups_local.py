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


# TODO: Validate attestations
# TODO: Allow users to "knock" or simpkly join depending on rules
# TODO: is_priveged flag to users and is_public to users and rooms
# TODO: Roles
# TODO: Audit log for admins (profile updates, membership changes, users who tried
#       to join but were rejected, etc)
# TODO: Flairs
# TODO: Add group memebership  /sync


def _create_rerouter(name):
    def f(self, group_id, *args, **kwargs):
        if self.is_mine_id(group_id):
            return getattr(self.groups_server_handler, name)(
                group_id, *args, **kwargs
            )

        repl_layer = self.hs.get_replication_layer()
        return getattr(repl_layer, name)(group_id, *args, **kwargs)
    return f


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
        self.attestations = hs.get_groups_attestation_signing()

        # Ensure attestations get renewed
        hs.get_groups_attestation_renewer()

    get_group_profile = _create_rerouter("get_group_profile")
    get_rooms_in_group = _create_rerouter("get_rooms_in_group")

    update_group_summary_room = _create_rerouter("update_group_summary_room")
    delete_group_summary_room = _create_rerouter("delete_group_summary_room")

    update_group_category = _create_rerouter("update_group_category")
    delete_group_category = _create_rerouter("delete_group_category")
    get_group_category = _create_rerouter("get_group_category")
    get_group_categories = _create_rerouter("get_group_categories")

    update_group_summary_user = _create_rerouter("update_group_summary_user")
    delete_group_summary_user = _create_rerouter("delete_group_summary_user")

    update_group_role = _create_rerouter("update_group_role")
    delete_group_role = _create_rerouter("delete_group_role")
    get_group_role = _create_rerouter("get_group_role")
    get_group_roles = _create_rerouter("get_group_roles")

    @defer.inlineCallbacks
    def get_group_summary(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.get_group_summary(
                group_id, requester_user_id
            )
            defer.returnValue(res)

        repl_layer = self.hs.get_replication_layer()
        res = yield repl_layer.get_group_summary(group_id, requester_user_id)

        chunk = res["users_section"]["users"]
        valid_users = []
        for entry in chunk:
            g_user_id = entry["user_id"]
            attestation = entry.pop("attestation")
            try:
                yield self.attestations.verify_attestation(
                    attestation,
                    group_id=group_id,
                    user_id=g_user_id,
                )
                valid_users.append(entry)
            except Exception as e:
                logger.info("Failed to verify user is in group: %s", e)

        res["users_section"]["users"] = valid_users

        res["users_section"]["users"].sort(key=lambda e: e.get("order", 0))
        res["rooms_section"]["rooms"].sort(key=lambda e: e.get("order", 0))

        defer.returnValue(res)

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
    def get_users_in_group(self, group_id, requester_user_id):
        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.get_users_in_group(
                group_id, requester_user_id
            )
            defer.returnValue(res)

        repl_layer = self.hs.get_replication_layer()
        res = yield repl_layer.get_users_in_group(group_id, requester_user_id)  # TODO

        chunk = res["chunk"]
        valid_entries = []
        for entry in chunk:
            g_user_id = entry["user_id"]
            attestation = entry.pop("attestation")
            try:
                yield self.attestations.verify_attestation(
                    attestation,
                    group_id=group_id,
                    user_id=g_user_id,
                )
                valid_entries.append(entry)
            except Exception as e:
                logger.info("Failed to verify user is in group: %s", e)

        res["chunk"] = valid_entries

        defer.returnValue(res)

    @defer.inlineCallbacks
    def join_group(self, group_id, user_id, content):
        raise NotImplementedError()  # TODO

    @defer.inlineCallbacks
    def accept_invite(self, group_id, user_id, content):
        if self.is_mine_id(group_id):
            yield self.groups_server_handler.accept_invite(
                group_id, user_id, content
            )
            local_attestation = None
            remote_attestation = None
        else:
            local_attestation = self.attestations.create_attestation(group_id, user_id)
            content["attestation"] = local_attestation

            repl_layer = self.hs.get_replication_layer()
            res = yield repl_layer.accept_group_invite(group_id, user_id, content)

            remote_attestation = res["attestation"]

            yield self.attestations.verify_attestation(
                remote_attestation,
                group_id=group_id,
                user_id=user_id,
            )

        yield self.store.register_user_group_membership(
            group_id, user_id,
            membership="join",
            is_admin=False,
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def invite(self, group_id, user_id, requester_user_id, config):
        content = {
            "requester_user_id": requester_user_id,
            "config": config,
        }
        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.invite_to_group(
                group_id, user_id, requester_user_id, content,
            )
        else:
            repl_layer = self.hs.get_replication_layer()
            res = yield repl_layer.invite_to_group(
                group_id, user_id, content,
            )

        defer.returnValue(res)

    @defer.inlineCallbacks
    def on_invite(self, group_id, user_id, content):
        # TODO: Support auto join and rejection

        if not self.is_mine_id(user_id):
            raise SynapseError(400, "User not on this server")

        local_profile = {}
        if "profile" in content:
            if "name" in content["profile"]:
                local_profile["name"] = content["profile"]["name"]
            if "avatar_url" in content["profile"]:
                local_profile["avatar_url"] = content["profile"]["avatar_url"]

        yield self.store.register_user_group_membership(
            group_id, user_id,
            membership="invite",
            content={"profile": local_profile, "inviter": content["inviter"]},
        )

        defer.returnValue({"state": "invite"})

    @defer.inlineCallbacks
    def remove_user_from_group(self, group_id, user_id, requester_user_id, content):
        if user_id == requester_user_id:
            yield self.store.register_user_group_membership(
                group_id, user_id,
                membership="leave",
            )

            # TODO: Should probably remember that we tried to leave so that we can
            # retry if the group server is currently down.

        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.remove_user_from_group(
                group_id, user_id, requester_user_id, content,
            )
        else:
            content["requester_user_id"] = requester_user_id
            repl_layer = self.hs.get_replication_layer()
            res = yield repl_layer.remove_user_from_group(
                group_id, user_id, content
            )  # TODO

        defer.returnValue(res)

    @defer.inlineCallbacks
    def user_removed_from_group(self, group_id, user_id, content):
        # TODO: Check if user in group
        yield self.store.register_user_group_membership(
            group_id, user_id,
            membership="leave",
        )

    @defer.inlineCallbacks
    def get_joined_groups(self, user_id):
        group_ids = yield self.store.get_joined_groups(user_id)
        defer.returnValue({"groups": group_ids})
