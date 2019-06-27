# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2018 New Vector Ltd
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

import logging

from six import iteritems

from twisted.internet import defer

from synapse.api.errors import HttpResponseException, RequestSendFailed, SynapseError
from synapse.types import get_domain_from_id

logger = logging.getLogger(__name__)


def _create_rerouter(func_name):
    """Returns a function that looks at the group id and calls the function
    on federation or the local group server if the group is local
    """

    def f(self, group_id, *args, **kwargs):
        if self.is_mine_id(group_id):
            return getattr(self.groups_server_handler, func_name)(
                group_id, *args, **kwargs
            )
        else:
            destination = get_domain_from_id(group_id)
            d = getattr(self.transport_client, func_name)(
                destination, group_id, *args, **kwargs
            )

            # Capture errors returned by the remote homeserver and
            # re-throw specific errors as SynapseErrors. This is so
            # when the remote end responds with things like 403 Not
            # In Group, we can communicate that to the client instead
            # of a 500.
            def http_response_errback(failure):
                failure.trap(HttpResponseException)
                e = failure.value
                raise e.to_synapse_error()

            def request_failed_errback(failure):
                failure.trap(RequestSendFailed)
                raise SynapseError(502, "Failed to contact group server")

            d.addErrback(http_response_errback)
            d.addErrback(request_failed_errback)
            return d

    return f


class GroupsLocalHandler(object):
    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.room_list_handler = hs.get_room_list_handler()
        self.groups_server_handler = hs.get_groups_server_handler()
        self.transport_client = hs.get_federation_transport_client()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.keyring = hs.get_keyring()
        self.is_mine_id = hs.is_mine_id
        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname
        self.notifier = hs.get_notifier()
        self.attestations = hs.get_groups_attestation_signing()

        self.profile_handler = hs.get_profile_handler()

        # Ensure attestations get renewed
        hs.get_groups_attestation_renewer()

    # The following functions merely route the query to the local groups server
    # or federation depending on if the group is local or remote

    get_group_profile = _create_rerouter("get_group_profile")
    update_group_profile = _create_rerouter("update_group_profile")
    get_rooms_in_group = _create_rerouter("get_rooms_in_group")

    get_invited_users_in_group = _create_rerouter("get_invited_users_in_group")

    add_room_to_group = _create_rerouter("add_room_to_group")
    update_room_in_group = _create_rerouter("update_room_in_group")
    remove_room_from_group = _create_rerouter("remove_room_from_group")

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

    set_group_join_policy = _create_rerouter("set_group_join_policy")

    @defer.inlineCallbacks
    def get_group_summary(self, group_id, requester_user_id):
        """Get the group summary for a group.

        If the group is remote we check that the users have valid attestations.
        """
        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.get_group_summary(
                group_id, requester_user_id
            )
        else:
            res = yield self.transport_client.get_group_summary(
                get_domain_from_id(group_id), group_id, requester_user_id
            )

            group_server_name = get_domain_from_id(group_id)

            # Loop through the users and validate the attestations.
            chunk = res["users_section"]["users"]
            valid_users = []
            for entry in chunk:
                g_user_id = entry["user_id"]
                attestation = entry.pop("attestation", {})
                try:
                    if get_domain_from_id(g_user_id) != group_server_name:
                        yield self.attestations.verify_attestation(
                            attestation,
                            group_id=group_id,
                            user_id=g_user_id,
                            server_name=get_domain_from_id(g_user_id),
                        )
                    valid_users.append(entry)
                except Exception as e:
                    logger.info("Failed to verify user is in group: %s", e)

            res["users_section"]["users"] = valid_users

            res["users_section"]["users"].sort(key=lambda e: e.get("order", 0))
            res["rooms_section"]["rooms"].sort(key=lambda e: e.get("order", 0))

        # Add `is_publicised` flag to indicate whether the user has publicised their
        # membership of the group on their profile
        result = yield self.store.get_publicised_groups_for_user(requester_user_id)
        is_publicised = group_id in result

        res.setdefault("user", {})["is_publicised"] = is_publicised

        defer.returnValue(res)

    @defer.inlineCallbacks
    def create_group(self, group_id, user_id, content):
        """Create a group
        """

        logger.info("Asking to create group with ID: %r", group_id)

        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.create_group(
                group_id, user_id, content
            )
            local_attestation = None
            remote_attestation = None
        else:
            local_attestation = self.attestations.create_attestation(group_id, user_id)
            content["attestation"] = local_attestation

            content["user_profile"] = yield self.profile_handler.get_profile(user_id)

            res = yield self.transport_client.create_group(
                get_domain_from_id(group_id), group_id, user_id, content
            )

            remote_attestation = res["attestation"]
            yield self.attestations.verify_attestation(
                remote_attestation,
                group_id=group_id,
                user_id=user_id,
                server_name=get_domain_from_id(group_id),
            )

        is_publicised = content.get("publicise", False)
        token = yield self.store.register_user_group_membership(
            group_id,
            user_id,
            membership="join",
            is_admin=True,
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
            is_publicised=is_publicised,
        )
        self.notifier.on_new_event("groups_key", token, users=[user_id])

        defer.returnValue(res)

    @defer.inlineCallbacks
    def get_users_in_group(self, group_id, requester_user_id):
        """Get users in a group
        """
        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.get_users_in_group(
                group_id, requester_user_id
            )
            defer.returnValue(res)

        group_server_name = get_domain_from_id(group_id)

        res = yield self.transport_client.get_users_in_group(
            get_domain_from_id(group_id), group_id, requester_user_id
        )

        chunk = res["chunk"]
        valid_entries = []
        for entry in chunk:
            g_user_id = entry["user_id"]
            attestation = entry.pop("attestation", {})
            try:
                if get_domain_from_id(g_user_id) != group_server_name:
                    yield self.attestations.verify_attestation(
                        attestation,
                        group_id=group_id,
                        user_id=g_user_id,
                        server_name=get_domain_from_id(g_user_id),
                    )
                valid_entries.append(entry)
            except Exception as e:
                logger.info("Failed to verify user is in group: %s", e)

        res["chunk"] = valid_entries

        defer.returnValue(res)

    @defer.inlineCallbacks
    def join_group(self, group_id, user_id, content):
        """Request to join a group
        """
        if self.is_mine_id(group_id):
            yield self.groups_server_handler.join_group(group_id, user_id, content)
            local_attestation = None
            remote_attestation = None
        else:
            local_attestation = self.attestations.create_attestation(group_id, user_id)
            content["attestation"] = local_attestation

            res = yield self.transport_client.join_group(
                get_domain_from_id(group_id), group_id, user_id, content
            )

            remote_attestation = res["attestation"]

            yield self.attestations.verify_attestation(
                remote_attestation,
                group_id=group_id,
                user_id=user_id,
                server_name=get_domain_from_id(group_id),
            )

        # TODO: Check that the group is public and we're being added publically
        is_publicised = content.get("publicise", False)

        token = yield self.store.register_user_group_membership(
            group_id,
            user_id,
            membership="join",
            is_admin=False,
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
            is_publicised=is_publicised,
        )
        self.notifier.on_new_event("groups_key", token, users=[user_id])

        defer.returnValue({})

    @defer.inlineCallbacks
    def accept_invite(self, group_id, user_id, content):
        """Accept an invite to a group
        """
        if self.is_mine_id(group_id):
            yield self.groups_server_handler.accept_invite(group_id, user_id, content)
            local_attestation = None
            remote_attestation = None
        else:
            local_attestation = self.attestations.create_attestation(group_id, user_id)
            content["attestation"] = local_attestation

            res = yield self.transport_client.accept_group_invite(
                get_domain_from_id(group_id), group_id, user_id, content
            )

            remote_attestation = res["attestation"]

            yield self.attestations.verify_attestation(
                remote_attestation,
                group_id=group_id,
                user_id=user_id,
                server_name=get_domain_from_id(group_id),
            )

        # TODO: Check that the group is public and we're being added publically
        is_publicised = content.get("publicise", False)

        token = yield self.store.register_user_group_membership(
            group_id,
            user_id,
            membership="join",
            is_admin=False,
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
            is_publicised=is_publicised,
        )
        self.notifier.on_new_event("groups_key", token, users=[user_id])

        defer.returnValue({})

    @defer.inlineCallbacks
    def invite(self, group_id, user_id, requester_user_id, config):
        """Invite a user to a group
        """
        content = {"requester_user_id": requester_user_id, "config": config}
        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.invite_to_group(
                group_id, user_id, requester_user_id, content
            )
        else:
            res = yield self.transport_client.invite_to_group(
                get_domain_from_id(group_id),
                group_id,
                user_id,
                requester_user_id,
                content,
            )

        defer.returnValue(res)

    @defer.inlineCallbacks
    def on_invite(self, group_id, user_id, content):
        """One of our users were invited to a group
        """
        # TODO: Support auto join and rejection

        if not self.is_mine_id(user_id):
            raise SynapseError(400, "User not on this server")

        local_profile = {}
        if "profile" in content:
            if "name" in content["profile"]:
                local_profile["name"] = content["profile"]["name"]
            if "avatar_url" in content["profile"]:
                local_profile["avatar_url"] = content["profile"]["avatar_url"]

        token = yield self.store.register_user_group_membership(
            group_id,
            user_id,
            membership="invite",
            content={"profile": local_profile, "inviter": content["inviter"]},
        )
        self.notifier.on_new_event("groups_key", token, users=[user_id])
        try:
            user_profile = yield self.profile_handler.get_profile(user_id)
        except Exception as e:
            logger.warn("No profile for user %s: %s", user_id, e)
            user_profile = {}

        defer.returnValue({"state": "invite", "user_profile": user_profile})

    @defer.inlineCallbacks
    def remove_user_from_group(self, group_id, user_id, requester_user_id, content):
        """Remove a user from a group
        """
        if user_id == requester_user_id:
            token = yield self.store.register_user_group_membership(
                group_id, user_id, membership="leave"
            )
            self.notifier.on_new_event("groups_key", token, users=[user_id])

            # TODO: Should probably remember that we tried to leave so that we can
            # retry if the group server is currently down.

        if self.is_mine_id(group_id):
            res = yield self.groups_server_handler.remove_user_from_group(
                group_id, user_id, requester_user_id, content
            )
        else:
            content["requester_user_id"] = requester_user_id
            res = yield self.transport_client.remove_user_from_group(
                get_domain_from_id(group_id),
                group_id,
                requester_user_id,
                user_id,
                content,
            )

        defer.returnValue(res)

    @defer.inlineCallbacks
    def user_removed_from_group(self, group_id, user_id, content):
        """One of our users was removed/kicked from a group
        """
        # TODO: Check if user in group
        token = yield self.store.register_user_group_membership(
            group_id, user_id, membership="leave"
        )
        self.notifier.on_new_event("groups_key", token, users=[user_id])

    @defer.inlineCallbacks
    def get_joined_groups(self, user_id):
        group_ids = yield self.store.get_joined_groups(user_id)
        defer.returnValue({"groups": group_ids})

    @defer.inlineCallbacks
    def get_publicised_groups_for_user(self, user_id):
        if self.hs.is_mine_id(user_id):
            result = yield self.store.get_publicised_groups_for_user(user_id)

            # Check AS associated groups for this user - this depends on the
            # RegExps in the AS registration file (under `users`)
            for app_service in self.store.get_app_services():
                result.extend(app_service.get_groups_for_user(user_id))

            defer.returnValue({"groups": result})
        else:
            bulk_result = yield self.transport_client.bulk_get_publicised_groups(
                get_domain_from_id(user_id), [user_id]
            )
            result = bulk_result.get("users", {}).get(user_id)
            # TODO: Verify attestations
            defer.returnValue({"groups": result})

    @defer.inlineCallbacks
    def bulk_get_publicised_groups(self, user_ids, proxy=True):
        destinations = {}
        local_users = set()

        for user_id in user_ids:
            if self.hs.is_mine_id(user_id):
                local_users.add(user_id)
            else:
                destinations.setdefault(get_domain_from_id(user_id), set()).add(user_id)

        if not proxy and destinations:
            raise SynapseError(400, "Some user_ids are not local")

        results = {}
        failed_results = []
        for destination, dest_user_ids in iteritems(destinations):
            try:
                r = yield self.transport_client.bulk_get_publicised_groups(
                    destination, list(dest_user_ids)
                )
                results.update(r["users"])
            except Exception:
                failed_results.extend(dest_user_ids)

        for uid in local_users:
            results[uid] = yield self.store.get_publicised_groups_for_user(uid)

            # Check AS associated groups for this user - this depends on the
            # RegExps in the AS registration file (under `users`)
            for app_service in self.store.get_app_services():
                results[uid].extend(app_service.get_groups_for_user(uid))

        defer.returnValue({"users": results})
