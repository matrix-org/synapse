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

from six import string_types

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.types import GroupID, RoomID, UserID, get_domain_from_id
from synapse.util.async_helpers import concurrently_execute

logger = logging.getLogger(__name__)


# TODO: Allow users to "knock" or simpkly join depending on rules
# TODO: Federation admin APIs
# TODO: is_priveged flag to users and is_public to users and rooms
# TODO: Audit log for admins (profile updates, membership changes, users who tried
#       to join but were rejected, etc)
# TODO: Flairs


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
        self.attestations = hs.get_groups_attestation_signing()
        self.transport_client = hs.get_federation_transport_client()
        self.profile_handler = hs.get_profile_handler()

        # Ensure attestations get renewed
        hs.get_groups_attestation_renewer()

    @defer.inlineCallbacks
    def check_group_is_ours(
        self, group_id, requester_user_id, and_exists=False, and_is_admin=None
    ):
        """Check that the group is ours, and optionally if it exists.

        If group does exist then return group.

        Args:
            group_id (str)
            and_exists (bool): whether to also check if group exists
            and_is_admin (str): whether to also check if given str is a user_id
                that is an admin
        """
        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Group not on this server")

        group = yield self.store.get_group(group_id)
        if and_exists and not group:
            raise SynapseError(404, "Unknown group")

        is_user_in_group = yield self.store.is_user_in_group(
            requester_user_id, group_id
        )
        if group and not is_user_in_group and not group["is_public"]:
            raise SynapseError(404, "Unknown group")

        if and_is_admin:
            is_admin = yield self.store.is_user_admin_in_group(group_id, and_is_admin)
            if not is_admin:
                raise SynapseError(403, "User is not admin in group")

        defer.returnValue(group)

    @defer.inlineCallbacks
    def get_group_summary(self, group_id, requester_user_id):
        """Get the summary for a group as seen by requester_user_id.

        The group summary consists of the profile of the room, and a curated
        list of users and rooms. These list *may* be organised by role/category.
        The roles/categories are ordered, and so are the users/rooms within them.

        A user/room may appear in multiple roles/categories.
        """
        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = yield self.store.is_user_in_group(
            requester_user_id, group_id
        )

        profile = yield self.get_group_profile(group_id, requester_user_id)

        users, roles = yield self.store.get_users_for_summary_by_role(
            group_id, include_private=is_user_in_group
        )

        # TODO: Add profiles to users

        rooms, categories = yield self.store.get_rooms_for_summary_by_category(
            group_id, include_private=is_user_in_group
        )

        for room_entry in rooms:
            room_id = room_entry["room_id"]
            joined_users = yield self.store.get_users_in_room(room_id)
            entry = yield self.room_list_handler.generate_room_entry(
                room_id, len(joined_users), with_alias=False, allow_private=True
            )
            entry = dict(entry)  # so we don't change whats cached
            entry.pop("room_id", None)

            room_entry["profile"] = entry

        rooms.sort(key=lambda e: e.get("order", 0))

        for entry in users:
            user_id = entry["user_id"]

            if not self.is_mine_id(requester_user_id):
                attestation = yield self.store.get_remote_attestation(group_id, user_id)
                if not attestation:
                    continue

                entry["attestation"] = attestation
            else:
                entry["attestation"] = self.attestations.create_attestation(
                    group_id, user_id
                )

            user_profile = yield self.profile_handler.get_profile_from_cache(user_id)
            entry.update(user_profile)

        users.sort(key=lambda e: e.get("order", 0))

        membership_info = yield self.store.get_users_membership_info_in_group(
            group_id, requester_user_id
        )

        defer.returnValue(
            {
                "profile": profile,
                "users_section": {
                    "users": users,
                    "roles": roles,
                    "total_user_count_estimate": 0,  # TODO
                },
                "rooms_section": {
                    "rooms": rooms,
                    "categories": categories,
                    "total_room_count_estimate": 0,  # TODO
                },
                "user": membership_info,
            }
        )

    @defer.inlineCallbacks
    def update_group_summary_room(
        self, group_id, requester_user_id, room_id, category_id, content
    ):
        """Add/update a room to the group summary
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        RoomID.from_string(room_id)  # Ensure valid room id

        order = content.get("order", None)

        is_public = _parse_visibility_from_contents(content)

        yield self.store.add_room_to_summary(
            group_id=group_id,
            room_id=room_id,
            category_id=category_id,
            order=order,
            is_public=is_public,
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def delete_group_summary_room(
        self, group_id, requester_user_id, room_id, category_id
    ):
        """Remove a room from the summary
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        yield self.store.remove_room_from_summary(
            group_id=group_id, room_id=room_id, category_id=category_id
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def set_group_join_policy(self, group_id, requester_user_id, content):
        """Sets the group join policy.

        Currently supported policies are:
         - "invite": an invite must be received and accepted in order to join.
         - "open": anyone can join.
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        join_policy = _parse_join_policy_from_contents(content)
        if join_policy is None:
            raise SynapseError(400, "No value specified for 'm.join_policy'")

        yield self.store.set_group_join_policy(group_id, join_policy=join_policy)

        defer.returnValue({})

    @defer.inlineCallbacks
    def get_group_categories(self, group_id, requester_user_id):
        """Get all categories in a group (as seen by user)
        """
        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        categories = yield self.store.get_group_categories(group_id=group_id)
        defer.returnValue({"categories": categories})

    @defer.inlineCallbacks
    def get_group_category(self, group_id, requester_user_id, category_id):
        """Get a specific category in a group (as seen by user)
        """
        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        res = yield self.store.get_group_category(
            group_id=group_id, category_id=category_id
        )

        defer.returnValue(res)

    @defer.inlineCallbacks
    def update_group_category(self, group_id, requester_user_id, category_id, content):
        """Add/Update a group category
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        is_public = _parse_visibility_from_contents(content)
        profile = content.get("profile")

        yield self.store.upsert_group_category(
            group_id=group_id,
            category_id=category_id,
            is_public=is_public,
            profile=profile,
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def delete_group_category(self, group_id, requester_user_id, category_id):
        """Delete a group category
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        yield self.store.remove_group_category(
            group_id=group_id, category_id=category_id
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def get_group_roles(self, group_id, requester_user_id):
        """Get all roles in a group (as seen by user)
        """
        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        roles = yield self.store.get_group_roles(group_id=group_id)
        defer.returnValue({"roles": roles})

    @defer.inlineCallbacks
    def get_group_role(self, group_id, requester_user_id, role_id):
        """Get a specific role in a group (as seen by user)
        """
        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        res = yield self.store.get_group_role(group_id=group_id, role_id=role_id)
        defer.returnValue(res)

    @defer.inlineCallbacks
    def update_group_role(self, group_id, requester_user_id, role_id, content):
        """Add/update a role in a group
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        is_public = _parse_visibility_from_contents(content)

        profile = content.get("profile")

        yield self.store.upsert_group_role(
            group_id=group_id, role_id=role_id, is_public=is_public, profile=profile
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def delete_group_role(self, group_id, requester_user_id, role_id):
        """Remove role from group
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        yield self.store.remove_group_role(group_id=group_id, role_id=role_id)

        defer.returnValue({})

    @defer.inlineCallbacks
    def update_group_summary_user(
        self, group_id, requester_user_id, user_id, role_id, content
    ):
        """Add/update a users entry in the group summary
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        order = content.get("order", None)

        is_public = _parse_visibility_from_contents(content)

        yield self.store.add_user_to_summary(
            group_id=group_id,
            user_id=user_id,
            role_id=role_id,
            order=order,
            is_public=is_public,
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def delete_group_summary_user(self, group_id, requester_user_id, user_id, role_id):
        """Remove a user from the group summary
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        yield self.store.remove_user_from_summary(
            group_id=group_id, user_id=user_id, role_id=role_id
        )

        defer.returnValue({})

    @defer.inlineCallbacks
    def get_group_profile(self, group_id, requester_user_id):
        """Get the group profile as seen by requester_user_id
        """

        yield self.check_group_is_ours(group_id, requester_user_id)

        group = yield self.store.get_group(group_id)

        if group:
            cols = [
                "name",
                "short_description",
                "long_description",
                "avatar_url",
                "is_public",
            ]
            group_description = {key: group[key] for key in cols}
            group_description["is_openly_joinable"] = group["join_policy"] == "open"

            defer.returnValue(group_description)
        else:
            raise SynapseError(404, "Unknown group")

    @defer.inlineCallbacks
    def update_group_profile(self, group_id, requester_user_id, content):
        """Update the group profile
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        profile = {}
        for keyname in ("name", "avatar_url", "short_description", "long_description"):
            if keyname in content:
                value = content[keyname]
                if not isinstance(value, string_types):
                    raise SynapseError(400, "%r value is not a string" % (keyname,))
                profile[keyname] = value

        yield self.store.update_group_profile(group_id, profile)

    @defer.inlineCallbacks
    def get_users_in_group(self, group_id, requester_user_id):
        """Get the users in group as seen by requester_user_id.

        The ordering is arbitrary at the moment
        """

        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = yield self.store.is_user_in_group(
            requester_user_id, group_id
        )

        user_results = yield self.store.get_users_in_group(
            group_id, include_private=is_user_in_group
        )

        chunk = []
        for user_result in user_results:
            g_user_id = user_result["user_id"]
            is_public = user_result["is_public"]
            is_privileged = user_result["is_admin"]

            entry = {"user_id": g_user_id}

            profile = yield self.profile_handler.get_profile_from_cache(g_user_id)
            entry.update(profile)

            entry["is_public"] = bool(is_public)
            entry["is_privileged"] = bool(is_privileged)

            if not self.is_mine_id(g_user_id):
                attestation = yield self.store.get_remote_attestation(
                    group_id, g_user_id
                )
                if not attestation:
                    continue

                entry["attestation"] = attestation
            else:
                entry["attestation"] = self.attestations.create_attestation(
                    group_id, g_user_id
                )

            chunk.append(entry)

        # TODO: If admin add lists of users whose attestations have timed out

        defer.returnValue(
            {"chunk": chunk, "total_user_count_estimate": len(user_results)}
        )

    @defer.inlineCallbacks
    def get_invited_users_in_group(self, group_id, requester_user_id):
        """Get the users that have been invited to a group as seen by requester_user_id.

        The ordering is arbitrary at the moment
        """

        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = yield self.store.is_user_in_group(
            requester_user_id, group_id
        )

        if not is_user_in_group:
            raise SynapseError(403, "User not in group")

        invited_users = yield self.store.get_invited_users_in_group(group_id)

        user_profiles = []

        for user_id in invited_users:
            user_profile = {"user_id": user_id}
            try:
                profile = yield self.profile_handler.get_profile_from_cache(user_id)
                user_profile.update(profile)
            except Exception as e:
                logger.warn("Error getting profile for %s: %s", user_id, e)
            user_profiles.append(user_profile)

        defer.returnValue(
            {"chunk": user_profiles, "total_user_count_estimate": len(invited_users)}
        )

    @defer.inlineCallbacks
    def get_rooms_in_group(self, group_id, requester_user_id):
        """Get the rooms in group as seen by requester_user_id

        This returns rooms in order of decreasing number of joined users
        """

        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = yield self.store.is_user_in_group(
            requester_user_id, group_id
        )

        room_results = yield self.store.get_rooms_in_group(
            group_id, include_private=is_user_in_group
        )

        chunk = []
        for room_result in room_results:
            room_id = room_result["room_id"]

            joined_users = yield self.store.get_users_in_room(room_id)
            entry = yield self.room_list_handler.generate_room_entry(
                room_id, len(joined_users), with_alias=False, allow_private=True
            )

            if not entry:
                continue

            entry["is_public"] = bool(room_result["is_public"])

            chunk.append(entry)

        chunk.sort(key=lambda e: -e["num_joined_members"])

        defer.returnValue(
            {"chunk": chunk, "total_room_count_estimate": len(room_results)}
        )

    @defer.inlineCallbacks
    def add_room_to_group(self, group_id, requester_user_id, room_id, content):
        """Add room to group
        """
        RoomID.from_string(room_id)  # Ensure valid room id

        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        is_public = _parse_visibility_from_contents(content)

        yield self.store.add_room_to_group(group_id, room_id, is_public=is_public)

        defer.returnValue({})

    @defer.inlineCallbacks
    def update_room_in_group(
        self, group_id, requester_user_id, room_id, config_key, content
    ):
        """Update room in group
        """
        RoomID.from_string(room_id)  # Ensure valid room id

        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        if config_key == "m.visibility":
            is_public = _parse_visibility_dict(content)

            yield self.store.update_room_in_group_visibility(
                group_id, room_id, is_public=is_public
            )
        else:
            raise SynapseError(400, "Uknown config option")

        defer.returnValue({})

    @defer.inlineCallbacks
    def remove_room_from_group(self, group_id, requester_user_id, room_id):
        """Remove room from group
        """
        yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        yield self.store.remove_room_from_group(group_id, room_id)

        defer.returnValue({})

    @defer.inlineCallbacks
    def invite_to_group(self, group_id, user_id, requester_user_id, content):
        """Invite user to group
        """

        group = yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        # TODO: Check if user knocked
        # TODO: Check if user is already invited

        content = {
            "profile": {"name": group["name"], "avatar_url": group["avatar_url"]},
            "inviter": requester_user_id,
        }

        if self.hs.is_mine_id(user_id):
            groups_local = self.hs.get_groups_local_handler()
            res = yield groups_local.on_invite(group_id, user_id, content)
            local_attestation = None
        else:
            local_attestation = self.attestations.create_attestation(group_id, user_id)
            content.update({"attestation": local_attestation})

            res = yield self.transport_client.invite_to_group_notification(
                get_domain_from_id(user_id), group_id, user_id, content
            )

            user_profile = res.get("user_profile", {})
            yield self.store.add_remote_profile_cache(
                user_id,
                displayname=user_profile.get("displayname"),
                avatar_url=user_profile.get("avatar_url"),
            )

        if res["state"] == "join":
            if not self.hs.is_mine_id(user_id):
                remote_attestation = res["attestation"]

                yield self.attestations.verify_attestation(
                    remote_attestation, user_id=user_id, group_id=group_id
                )
            else:
                remote_attestation = None

            yield self.store.add_user_to_group(
                group_id,
                user_id,
                is_admin=False,
                is_public=False,  # TODO
                local_attestation=local_attestation,
                remote_attestation=remote_attestation,
            )
        elif res["state"] == "invite":
            yield self.store.add_group_invite(group_id, user_id)
            defer.returnValue({"state": "invite"})
        elif res["state"] == "reject":
            defer.returnValue({"state": "reject"})
        else:
            raise SynapseError(502, "Unknown state returned by HS")

    @defer.inlineCallbacks
    def _add_user(self, group_id, user_id, content):
        """Add a user to a group based on a content dict.

        See accept_invite, join_group.
        """
        if not self.hs.is_mine_id(user_id):
            local_attestation = self.attestations.create_attestation(group_id, user_id)

            remote_attestation = content["attestation"]

            yield self.attestations.verify_attestation(
                remote_attestation, user_id=user_id, group_id=group_id
            )
        else:
            local_attestation = None
            remote_attestation = None

        is_public = _parse_visibility_from_contents(content)

        yield self.store.add_user_to_group(
            group_id,
            user_id,
            is_admin=False,
            is_public=is_public,
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
        )

        defer.returnValue(local_attestation)

    @defer.inlineCallbacks
    def accept_invite(self, group_id, requester_user_id, content):
        """User tries to accept an invite to the group.

        This is different from them asking to join, and so should error if no
        invite exists (and they're not a member of the group)
        """

        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_invited = yield self.store.is_user_invited_to_local_group(
            group_id, requester_user_id
        )
        if not is_invited:
            raise SynapseError(403, "User not invited to group")

        local_attestation = yield self._add_user(group_id, requester_user_id, content)

        defer.returnValue({"state": "join", "attestation": local_attestation})

    @defer.inlineCallbacks
    def join_group(self, group_id, requester_user_id, content):
        """User tries to join the group.

        This will error if the group requires an invite/knock to join
        """

        group_info = yield self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True
        )
        if group_info["join_policy"] != "open":
            raise SynapseError(403, "Group is not publicly joinable")

        local_attestation = yield self._add_user(group_id, requester_user_id, content)

        defer.returnValue({"state": "join", "attestation": local_attestation})

    @defer.inlineCallbacks
    def knock(self, group_id, requester_user_id, content):
        """A user requests becoming a member of the group
        """
        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        raise NotImplementedError()

    @defer.inlineCallbacks
    def accept_knock(self, group_id, requester_user_id, content):
        """Accept a users knock to the room.

        Errors if the user hasn't knocked, rather than inviting them.
        """

        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        raise NotImplementedError()

    @defer.inlineCallbacks
    def remove_user_from_group(self, group_id, user_id, requester_user_id, content):
        """Remove a user from the group; either a user is leaving or an admin
        kicked them.
        """

        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_kick = False
        if requester_user_id != user_id:
            is_admin = yield self.store.is_user_admin_in_group(
                group_id, requester_user_id
            )
            if not is_admin:
                raise SynapseError(403, "User is not admin in group")

            is_kick = True

        yield self.store.remove_user_from_group(group_id, user_id)

        if is_kick:
            if self.hs.is_mine_id(user_id):
                groups_local = self.hs.get_groups_local_handler()
                yield groups_local.user_removed_from_group(group_id, user_id, {})
            else:
                yield self.transport_client.remove_user_from_group_notification(
                    get_domain_from_id(user_id), group_id, user_id, {}
                )

        if not self.hs.is_mine_id(user_id):
            yield self.store.maybe_delete_remote_profile_cache(user_id)

        defer.returnValue({})

    @defer.inlineCallbacks
    def create_group(self, group_id, requester_user_id, content):
        group = yield self.check_group_is_ours(group_id, requester_user_id)

        logger.info("Attempting to create group with ID: %r", group_id)

        # parsing the id into a GroupID validates it.
        group_id_obj = GroupID.from_string(group_id)

        if group:
            raise SynapseError(400, "Group already exists")

        is_admin = yield self.auth.is_server_admin(
            UserID.from_string(requester_user_id)
        )
        if not is_admin:
            if not self.hs.config.enable_group_creation:
                raise SynapseError(
                    403, "Only a server admin can create groups on this server"
                )
            localpart = group_id_obj.localpart
            if not localpart.startswith(self.hs.config.group_creation_prefix):
                raise SynapseError(
                    400,
                    "Can only create groups with prefix %r on this server"
                    % (self.hs.config.group_creation_prefix,),
                )

        profile = content.get("profile", {})
        name = profile.get("name")
        avatar_url = profile.get("avatar_url")
        short_description = profile.get("short_description")
        long_description = profile.get("long_description")
        user_profile = content.get("user_profile", {})

        yield self.store.create_group(
            group_id,
            requester_user_id,
            name=name,
            avatar_url=avatar_url,
            short_description=short_description,
            long_description=long_description,
        )

        if not self.hs.is_mine_id(requester_user_id):
            remote_attestation = content["attestation"]

            yield self.attestations.verify_attestation(
                remote_attestation, user_id=requester_user_id, group_id=group_id
            )

            local_attestation = self.attestations.create_attestation(
                group_id, requester_user_id
            )
        else:
            local_attestation = None
            remote_attestation = None

        yield self.store.add_user_to_group(
            group_id,
            requester_user_id,
            is_admin=True,
            is_public=True,  # TODO
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
        )

        if not self.hs.is_mine_id(requester_user_id):
            yield self.store.add_remote_profile_cache(
                requester_user_id,
                displayname=user_profile.get("displayname"),
                avatar_url=user_profile.get("avatar_url"),
            )

        defer.returnValue({"group_id": group_id})

    @defer.inlineCallbacks
    def delete_group(self, group_id, requester_user_id):
        """Deletes a group, kicking out all current members.

        Only group admins or server admins can call this request

        Args:
            group_id (str)
            request_user_id (str)

        Returns:
            Deferred
        """

        yield self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        # Only server admins or group admins can delete groups.

        is_admin = yield self.store.is_user_admin_in_group(group_id, requester_user_id)

        if not is_admin:
            is_admin = yield self.auth.is_server_admin(
                UserID.from_string(requester_user_id)
            )

        if not is_admin:
            raise SynapseError(403, "User is not an admin")

        # Before deleting the group lets kick everyone out of it
        users = yield self.store.get_users_in_group(group_id, include_private=True)

        @defer.inlineCallbacks
        def _kick_user_from_group(user_id):
            if self.hs.is_mine_id(user_id):
                groups_local = self.hs.get_groups_local_handler()
                yield groups_local.user_removed_from_group(group_id, user_id, {})
            else:
                yield self.transport_client.remove_user_from_group_notification(
                    get_domain_from_id(user_id), group_id, user_id, {}
                )
                yield self.store.maybe_delete_remote_profile_cache(user_id)

        # We kick users out in the order of:
        #   1. Non-admins
        #   2. Other admins
        #   3. The requester
        #
        # This is so that if the deletion fails for some reason other admins or
        # the requester still has auth to retry.
        non_admins = []
        admins = []
        for u in users:
            if u["user_id"] == requester_user_id:
                continue
            if u["is_admin"]:
                admins.append(u["user_id"])
            else:
                non_admins.append(u["user_id"])

        yield concurrently_execute(_kick_user_from_group, non_admins, 10)
        yield concurrently_execute(_kick_user_from_group, admins, 10)
        yield _kick_user_from_group(requester_user_id)

        yield self.store.delete_group(group_id)


def _parse_join_policy_from_contents(content):
    """Given a content for a request, return the specified join policy or None
    """

    join_policy_dict = content.get("m.join_policy")
    if join_policy_dict:
        return _parse_join_policy_dict(join_policy_dict)
    else:
        return None


def _parse_join_policy_dict(join_policy_dict):
    """Given a dict for the "m.join_policy" config return the join policy specified
    """
    join_policy_type = join_policy_dict.get("type")
    if not join_policy_type:
        return "invite"

    if join_policy_type not in ("invite", "open"):
        raise SynapseError(400, "Synapse only supports 'invite'/'open' join rule")
    return join_policy_type


def _parse_visibility_from_contents(content):
    """Given a content for a request parse out whether the entity should be
    public or not
    """

    visibility = content.get("m.visibility")
    if visibility:
        return _parse_visibility_dict(visibility)
    else:
        is_public = True

    return is_public


def _parse_visibility_dict(visibility):
    """Given a dict for the "m.visibility" config return if the entity should
    be public or not
    """
    vis_type = visibility.get("type")
    if not vis_type:
        return True

    if vis_type not in ("public", "private"):
        raise SynapseError(400, "Synapse only supports 'public'/'private' visibility")
    return vis_type == "public"
