# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2019 Michael Telatynski <7t3chguy@gmail.com>
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
from typing import TYPE_CHECKING, Optional

from synapse.api.errors import Codes, SynapseError
from synapse.handlers.groups_local import GroupsLocalHandler
from synapse.handlers.profile import MAX_AVATAR_URL_LEN, MAX_DISPLAYNAME_LEN
from synapse.types import GroupID, JsonDict, RoomID, UserID, get_domain_from_id
from synapse.util.async_helpers import concurrently_execute

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# TODO: Allow users to "knock" or simply join depending on rules
# TODO: Federation admin APIs
# TODO: is_privileged flag to users and is_public to users and rooms
# TODO: Audit log for admins (profile updates, membership changes, users who tried
#       to join but were rejected, etc)
# TODO: Flairs


# Note that the maximum lengths are somewhat arbitrary.
MAX_SHORT_DESC_LEN = 1000
MAX_LONG_DESC_LEN = 10000


class GroupsServerWorkerHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastore()
        self.room_list_handler = hs.get_room_list_handler()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.keyring = hs.get_keyring()
        self.is_mine_id = hs.is_mine_id
        self.signing_key = hs.signing_key
        self.server_name = hs.hostname
        self.attestations = hs.get_groups_attestation_signing()
        self.transport_client = hs.get_federation_transport_client()
        self.profile_handler = hs.get_profile_handler()

    async def check_group_is_ours(
        self,
        group_id: str,
        requester_user_id: str,
        and_exists: bool = False,
        and_is_admin: Optional[str] = None,
    ) -> Optional[dict]:
        """Check that the group is ours, and optionally if it exists.

        If group does exist then return group.

        Args:
            group_id: The group ID to check.
            requester_user_id: The user ID of the requester.
            and_exists: whether to also check if group exists
            and_is_admin: whether to also check if given str is a user_id
                that is an admin
        """
        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Group not on this server")

        group = await self.store.get_group(group_id)
        if and_exists and not group:
            raise SynapseError(404, "Unknown group")

        is_user_in_group = await self.store.is_user_in_group(
            requester_user_id, group_id
        )
        if group and not is_user_in_group and not group["is_public"]:
            raise SynapseError(404, "Unknown group")

        if and_is_admin:
            is_admin = await self.store.is_user_admin_in_group(group_id, and_is_admin)
            if not is_admin:
                raise SynapseError(403, "User is not admin in group")

        return group

    async def get_group_summary(
        self, group_id: str, requester_user_id: str
    ) -> JsonDict:
        """Get the summary for a group as seen by requester_user_id.

        The group summary consists of the profile of the room, and a curated
        list of users and rooms. These list *may* be organised by role/category.
        The roles/categories are ordered, and so are the users/rooms within them.

        A user/room may appear in multiple roles/categories.
        """
        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = await self.store.is_user_in_group(
            requester_user_id, group_id
        )

        profile = await self.get_group_profile(group_id, requester_user_id)

        users, roles = await self.store.get_users_for_summary_by_role(
            group_id, include_private=is_user_in_group
        )

        # TODO: Add profiles to users

        rooms, categories = await self.store.get_rooms_for_summary_by_category(
            group_id, include_private=is_user_in_group
        )

        for room_entry in rooms:
            room_id = room_entry["room_id"]
            joined_users = await self.store.get_users_in_room(room_id)
            entry = await self.room_list_handler.generate_room_entry(
                room_id, len(joined_users), with_alias=False, allow_private=True
            )
            if entry is None:
                continue
            entry = dict(entry)  # so we don't change what's cached
            entry.pop("room_id", None)

            room_entry["profile"] = entry

        rooms.sort(key=lambda e: e.get("order", 0))

        for user in users:
            user_id = user["user_id"]

            if not self.is_mine_id(requester_user_id):
                attestation = await self.store.get_remote_attestation(group_id, user_id)
                if not attestation:
                    continue

                user["attestation"] = attestation
            else:
                user["attestation"] = self.attestations.create_attestation(
                    group_id, user_id
                )

            user_profile = await self.profile_handler.get_profile_from_cache(user_id)
            user.update(user_profile)

        users.sort(key=lambda e: e.get("order", 0))

        membership_info = await self.store.get_users_membership_info_in_group(
            group_id, requester_user_id
        )

        return {
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

    async def get_group_categories(
        self, group_id: str, requester_user_id: str
    ) -> JsonDict:
        """Get all categories in a group (as seen by user)"""
        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        categories = await self.store.get_group_categories(group_id=group_id)
        return {"categories": categories}

    async def get_group_category(
        self, group_id: str, requester_user_id: str, category_id: str
    ) -> JsonDict:
        """Get a specific category in a group (as seen by user)"""
        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        return await self.store.get_group_category(
            group_id=group_id, category_id=category_id
        )

    async def get_group_roles(self, group_id: str, requester_user_id: str) -> JsonDict:
        """Get all roles in a group (as seen by user)"""
        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        roles = await self.store.get_group_roles(group_id=group_id)
        return {"roles": roles}

    async def get_group_role(
        self, group_id: str, requester_user_id: str, role_id: str
    ) -> JsonDict:
        """Get a specific role in a group (as seen by user)"""
        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        return await self.store.get_group_role(group_id=group_id, role_id=role_id)

    async def get_group_profile(
        self, group_id: str, requester_user_id: str
    ) -> JsonDict:
        """Get the group profile as seen by requester_user_id"""

        await self.check_group_is_ours(group_id, requester_user_id)

        group = await self.store.get_group(group_id)

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

            return group_description
        else:
            raise SynapseError(404, "Unknown group")

    async def get_users_in_group(
        self, group_id: str, requester_user_id: str
    ) -> JsonDict:
        """Get the users in group as seen by requester_user_id.

        The ordering is arbitrary at the moment
        """

        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = await self.store.is_user_in_group(
            requester_user_id, group_id
        )

        user_results = await self.store.get_users_in_group(
            group_id, include_private=is_user_in_group
        )

        chunk = []
        for user_result in user_results:
            g_user_id = user_result["user_id"]
            is_public = user_result["is_public"]
            is_privileged = user_result["is_admin"]

            entry = {"user_id": g_user_id}

            profile = await self.profile_handler.get_profile_from_cache(g_user_id)
            entry.update(profile)

            entry["is_public"] = bool(is_public)
            entry["is_privileged"] = bool(is_privileged)

            if not self.is_mine_id(g_user_id):
                attestation = await self.store.get_remote_attestation(
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

        return {"chunk": chunk, "total_user_count_estimate": len(user_results)}

    async def get_invited_users_in_group(
        self, group_id: str, requester_user_id: str
    ) -> JsonDict:
        """Get the users that have been invited to a group as seen by requester_user_id.

        The ordering is arbitrary at the moment
        """

        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = await self.store.is_user_in_group(
            requester_user_id, group_id
        )

        if not is_user_in_group:
            raise SynapseError(403, "User not in group")

        invited_users = await self.store.get_invited_users_in_group(group_id)

        user_profiles = []

        for user_id in invited_users:
            user_profile = {"user_id": user_id}
            try:
                profile = await self.profile_handler.get_profile_from_cache(user_id)
                user_profile.update(profile)
            except Exception as e:
                logger.warning("Error getting profile for %s: %s", user_id, e)
            user_profiles.append(user_profile)

        return {"chunk": user_profiles, "total_user_count_estimate": len(invited_users)}

    async def get_rooms_in_group(
        self, group_id: str, requester_user_id: str
    ) -> JsonDict:
        """Get the rooms in group as seen by requester_user_id

        This returns rooms in order of decreasing number of joined users
        """

        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_user_in_group = await self.store.is_user_in_group(
            requester_user_id, group_id
        )

        room_results = await self.store.get_rooms_in_group(
            group_id, include_private=is_user_in_group
        )

        chunk = []
        for room_result in room_results:
            room_id = room_result["room_id"]

            joined_users = await self.store.get_users_in_room(room_id)
            entry = await self.room_list_handler.generate_room_entry(
                room_id, len(joined_users), with_alias=False, allow_private=True
            )

            if not entry:
                continue

            entry["is_public"] = bool(room_result["is_public"])

            chunk.append(entry)

        chunk.sort(key=lambda e: -e["num_joined_members"])

        return {"chunk": chunk, "total_room_count_estimate": len(room_results)}


class GroupsServerHandler(GroupsServerWorkerHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        # Ensure attestations get renewed
        hs.get_groups_attestation_renewer()

    async def update_group_summary_room(
        self,
        group_id: str,
        requester_user_id: str,
        room_id: str,
        category_id: str,
        content: JsonDict,
    ) -> JsonDict:
        """Add/update a room to the group summary"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        RoomID.from_string(room_id)  # Ensure valid room id

        order = content.get("order", None)

        is_public = _parse_visibility_from_contents(content)

        await self.store.add_room_to_summary(
            group_id=group_id,
            room_id=room_id,
            category_id=category_id,
            order=order,
            is_public=is_public,
        )

        return {}

    async def delete_group_summary_room(
        self, group_id: str, requester_user_id: str, room_id: str, category_id: str
    ) -> JsonDict:
        """Remove a room from the summary"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        await self.store.remove_room_from_summary(
            group_id=group_id, room_id=room_id, category_id=category_id
        )

        return {}

    async def set_group_join_policy(
        self, group_id: str, requester_user_id: str, content: JsonDict
    ) -> JsonDict:
        """Sets the group join policy.

        Currently supported policies are:
         - "invite": an invite must be received and accepted in order to join.
         - "open": anyone can join.
        """
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        join_policy = _parse_join_policy_from_contents(content)
        if join_policy is None:
            raise SynapseError(400, "No value specified for 'm.join_policy'")

        await self.store.set_group_join_policy(group_id, join_policy=join_policy)

        return {}

    async def update_group_category(
        self, group_id: str, requester_user_id: str, category_id: str, content: JsonDict
    ) -> JsonDict:
        """Add/Update a group category"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        is_public = _parse_visibility_from_contents(content)
        profile = content.get("profile")

        await self.store.upsert_group_category(
            group_id=group_id,
            category_id=category_id,
            is_public=is_public,
            profile=profile,
        )

        return {}

    async def delete_group_category(
        self, group_id: str, requester_user_id: str, category_id: str
    ) -> JsonDict:
        """Delete a group category"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        await self.store.remove_group_category(
            group_id=group_id, category_id=category_id
        )

        return {}

    async def update_group_role(
        self, group_id: str, requester_user_id: str, role_id: str, content: JsonDict
    ) -> JsonDict:
        """Add/update a role in a group"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        is_public = _parse_visibility_from_contents(content)

        profile = content.get("profile")

        await self.store.upsert_group_role(
            group_id=group_id, role_id=role_id, is_public=is_public, profile=profile
        )

        return {}

    async def delete_group_role(
        self, group_id: str, requester_user_id: str, role_id: str
    ) -> JsonDict:
        """Remove role from group"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        await self.store.remove_group_role(group_id=group_id, role_id=role_id)

        return {}

    async def update_group_summary_user(
        self,
        group_id: str,
        requester_user_id: str,
        user_id: str,
        role_id: str,
        content: JsonDict,
    ) -> JsonDict:
        """Add/update a users entry in the group summary"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        order = content.get("order", None)

        is_public = _parse_visibility_from_contents(content)

        await self.store.add_user_to_summary(
            group_id=group_id,
            user_id=user_id,
            role_id=role_id,
            order=order,
            is_public=is_public,
        )

        return {}

    async def delete_group_summary_user(
        self, group_id: str, requester_user_id: str, user_id: str, role_id: str
    ) -> JsonDict:
        """Remove a user from the group summary"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        await self.store.remove_user_from_summary(
            group_id=group_id, user_id=user_id, role_id=role_id
        )

        return {}

    async def update_group_profile(
        self, group_id: str, requester_user_id: str, content: JsonDict
    ) -> None:
        """Update the group profile"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        profile = {}
        for keyname, max_length in (
            ("name", MAX_DISPLAYNAME_LEN),
            ("avatar_url", MAX_AVATAR_URL_LEN),
            ("short_description", MAX_SHORT_DESC_LEN),
            ("long_description", MAX_LONG_DESC_LEN),
        ):
            if keyname in content:
                value = content[keyname]
                if not isinstance(value, str):
                    raise SynapseError(
                        400,
                        "%r value is not a string" % (keyname,),
                        errcode=Codes.INVALID_PARAM,
                    )
                if len(value) > max_length:
                    raise SynapseError(
                        400,
                        "Invalid %s parameter" % (keyname,),
                        errcode=Codes.INVALID_PARAM,
                    )
                profile[keyname] = value

        await self.store.update_group_profile(group_id, profile)

    async def add_room_to_group(
        self, group_id: str, requester_user_id: str, room_id: str, content: JsonDict
    ) -> JsonDict:
        """Add room to group"""
        RoomID.from_string(room_id)  # Ensure valid room id

        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        is_public = _parse_visibility_from_contents(content)

        await self.store.add_room_to_group(group_id, room_id, is_public=is_public)

        return {}

    async def update_room_in_group(
        self,
        group_id: str,
        requester_user_id: str,
        room_id: str,
        config_key: str,
        content: JsonDict,
    ) -> JsonDict:
        """Update room in group"""
        RoomID.from_string(room_id)  # Ensure valid room id

        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        if config_key == "m.visibility":
            is_public = _parse_visibility_dict(content)

            await self.store.update_room_in_group_visibility(
                group_id, room_id, is_public=is_public
            )
        else:
            raise SynapseError(400, "Unknown config option")

        return {}

    async def remove_room_from_group(
        self, group_id: str, requester_user_id: str, room_id: str
    ) -> JsonDict:
        """Remove room from group"""
        await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )

        await self.store.remove_room_from_group(group_id, room_id)

        return {}

    async def invite_to_group(
        self, group_id: str, user_id: str, requester_user_id: str, content: JsonDict
    ) -> JsonDict:
        """Invite user to group"""

        group = await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True, and_is_admin=requester_user_id
        )
        if not group:
            raise SynapseError(400, "Group does not exist", errcode=Codes.BAD_STATE)

        # TODO: Check if user knocked

        invited_users = await self.store.get_invited_users_in_group(group_id)
        if user_id in invited_users:
            raise SynapseError(
                400, "User already invited to group", errcode=Codes.BAD_STATE
            )

        user_results = await self.store.get_users_in_group(
            group_id, include_private=True
        )
        if user_id in (user_result["user_id"] for user_result in user_results):
            raise SynapseError(400, "User already in group")

        content = {
            "profile": {"name": group["name"], "avatar_url": group["avatar_url"]},
            "inviter": requester_user_id,
        }

        if self.hs.is_mine_id(user_id):
            groups_local = self.hs.get_groups_local_handler()
            assert isinstance(
                groups_local, GroupsLocalHandler
            ), "Workers cannot invites users to groups."
            res = await groups_local.on_invite(group_id, user_id, content)
            local_attestation = None
        else:
            local_attestation = self.attestations.create_attestation(group_id, user_id)
            content.update({"attestation": local_attestation})

            res = await self.transport_client.invite_to_group_notification(
                get_domain_from_id(user_id), group_id, user_id, content
            )

            user_profile = res.get("user_profile", {})
            await self.store.add_remote_profile_cache(
                user_id,
                displayname=user_profile.get("displayname"),
                avatar_url=user_profile.get("avatar_url"),
            )

        if res["state"] == "join":
            if not self.hs.is_mine_id(user_id):
                remote_attestation = res["attestation"]

                await self.attestations.verify_attestation(
                    remote_attestation, user_id=user_id, group_id=group_id
                )
            else:
                remote_attestation = None

            await self.store.add_user_to_group(
                group_id,
                user_id,
                is_admin=False,
                is_public=False,  # TODO
                local_attestation=local_attestation,
                remote_attestation=remote_attestation,
            )
            return {"state": "join"}
        elif res["state"] == "invite":
            await self.store.add_group_invite(group_id, user_id)
            return {"state": "invite"}
        elif res["state"] == "reject":
            return {"state": "reject"}
        else:
            raise SynapseError(502, "Unknown state returned by HS")

    async def _add_user(
        self, group_id: str, user_id: str, content: JsonDict
    ) -> Optional[JsonDict]:
        """Add a user to a group based on a content dict.

        See accept_invite, join_group.
        """
        if not self.hs.is_mine_id(user_id):
            local_attestation = self.attestations.create_attestation(
                group_id, user_id
            )  # type: Optional[JsonDict]

            remote_attestation = content["attestation"]

            await self.attestations.verify_attestation(
                remote_attestation, user_id=user_id, group_id=group_id
            )
        else:
            local_attestation = None
            remote_attestation = None

        is_public = _parse_visibility_from_contents(content)

        await self.store.add_user_to_group(
            group_id,
            user_id,
            is_admin=False,
            is_public=is_public,
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
        )

        return local_attestation

    async def accept_invite(
        self, group_id: str, requester_user_id: str, content: JsonDict
    ) -> JsonDict:
        """User tries to accept an invite to the group.

        This is different from them asking to join, and so should error if no
        invite exists (and they're not a member of the group)
        """

        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_invited = await self.store.is_user_invited_to_local_group(
            group_id, requester_user_id
        )
        if not is_invited:
            raise SynapseError(403, "User not invited to group")

        local_attestation = await self._add_user(group_id, requester_user_id, content)

        return {"state": "join", "attestation": local_attestation}

    async def join_group(
        self, group_id: str, requester_user_id: str, content: JsonDict
    ) -> JsonDict:
        """User tries to join the group.

        This will error if the group requires an invite/knock to join
        """

        group_info = await self.check_group_is_ours(
            group_id, requester_user_id, and_exists=True
        )
        if not group_info:
            raise SynapseError(404, "Group does not exist", errcode=Codes.NOT_FOUND)
        if group_info["join_policy"] != "open":
            raise SynapseError(403, "Group is not publicly joinable")

        local_attestation = await self._add_user(group_id, requester_user_id, content)

        return {"state": "join", "attestation": local_attestation}

    async def remove_user_from_group(
        self, group_id: str, user_id: str, requester_user_id: str, content: JsonDict
    ) -> JsonDict:
        """Remove a user from the group; either a user is leaving or an admin
        kicked them.
        """

        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        is_kick = False
        if requester_user_id != user_id:
            is_admin = await self.store.is_user_admin_in_group(
                group_id, requester_user_id
            )
            if not is_admin:
                raise SynapseError(403, "User is not admin in group")

            is_kick = True

        await self.store.remove_user_from_group(group_id, user_id)

        if is_kick:
            if self.hs.is_mine_id(user_id):
                groups_local = self.hs.get_groups_local_handler()
                assert isinstance(
                    groups_local, GroupsLocalHandler
                ), "Workers cannot remove users from groups."
                await groups_local.user_removed_from_group(group_id, user_id, {})
            else:
                await self.transport_client.remove_user_from_group_notification(
                    get_domain_from_id(user_id), group_id, user_id, {}
                )

        if not self.hs.is_mine_id(user_id):
            await self.store.maybe_delete_remote_profile_cache(user_id)

        # Delete group if the last user has left
        users = await self.store.get_users_in_group(group_id, include_private=True)
        if not users:
            await self.store.delete_group(group_id)

        return {}

    async def create_group(
        self, group_id: str, requester_user_id: str, content: JsonDict
    ) -> JsonDict:
        logger.info("Attempting to create group with ID: %r", group_id)

        # parsing the id into a GroupID validates it.
        group_id_obj = GroupID.from_string(group_id)

        group = await self.check_group_is_ours(group_id, requester_user_id)
        if group:
            raise SynapseError(400, "Group already exists")

        is_admin = await self.auth.is_server_admin(
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

        await self.store.create_group(
            group_id,
            requester_user_id,
            name=name,
            avatar_url=avatar_url,
            short_description=short_description,
            long_description=long_description,
        )

        if not self.hs.is_mine_id(requester_user_id):
            remote_attestation = content["attestation"]

            await self.attestations.verify_attestation(
                remote_attestation, user_id=requester_user_id, group_id=group_id
            )

            local_attestation = self.attestations.create_attestation(
                group_id, requester_user_id
            )  # type: Optional[JsonDict]
        else:
            local_attestation = None
            remote_attestation = None

        await self.store.add_user_to_group(
            group_id,
            requester_user_id,
            is_admin=True,
            is_public=True,  # TODO
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
        )

        if not self.hs.is_mine_id(requester_user_id):
            await self.store.add_remote_profile_cache(
                requester_user_id,
                displayname=user_profile.get("displayname"),
                avatar_url=user_profile.get("avatar_url"),
            )

        return {"group_id": group_id}

    async def delete_group(self, group_id: str, requester_user_id: str) -> None:
        """Deletes a group, kicking out all current members.

        Only group admins or server admins can call this request

        Args:
            group_id: The group ID to delete.
            requester_user_id: The user requesting to delete the group.
        """

        await self.check_group_is_ours(group_id, requester_user_id, and_exists=True)

        # Only server admins or group admins can delete groups.

        is_admin = await self.store.is_user_admin_in_group(group_id, requester_user_id)

        if not is_admin:
            is_admin = await self.auth.is_server_admin(
                UserID.from_string(requester_user_id)
            )

        if not is_admin:
            raise SynapseError(403, "User is not an admin")

        # Before deleting the group lets kick everyone out of it
        users = await self.store.get_users_in_group(group_id, include_private=True)

        async def _kick_user_from_group(user_id):
            if self.hs.is_mine_id(user_id):
                groups_local = self.hs.get_groups_local_handler()
                assert isinstance(
                    groups_local, GroupsLocalHandler
                ), "Workers cannot kick users from groups."
                await groups_local.user_removed_from_group(group_id, user_id, {})
            else:
                await self.transport_client.remove_user_from_group_notification(
                    get_domain_from_id(user_id), group_id, user_id, {}
                )
                await self.store.maybe_delete_remote_profile_cache(user_id)

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

        await concurrently_execute(_kick_user_from_group, non_admins, 10)
        await concurrently_execute(_kick_user_from_group, admins, 10)
        await _kick_user_from_group(requester_user_id)

        await self.store.delete_group(group_id)


def _parse_join_policy_from_contents(content: JsonDict) -> Optional[str]:
    """Given a content for a request, return the specified join policy or None"""

    join_policy_dict = content.get("m.join_policy")
    if join_policy_dict:
        return _parse_join_policy_dict(join_policy_dict)
    else:
        return None


def _parse_join_policy_dict(join_policy_dict: JsonDict) -> str:
    """Given a dict for the "m.join_policy" config return the join policy specified"""
    join_policy_type = join_policy_dict.get("type")
    if not join_policy_type:
        return "invite"

    if join_policy_type not in ("invite", "open"):
        raise SynapseError(400, "Synapse only supports 'invite'/'open' join rule")
    return join_policy_type


def _parse_visibility_from_contents(content: JsonDict) -> bool:
    """Given a content for a request parse out whether the entity should be
    public or not
    """

    visibility = content.get("m.visibility")
    if visibility:
        return _parse_visibility_dict(visibility)
    else:
        is_public = True

    return is_public


def _parse_visibility_dict(visibility: JsonDict) -> bool:
    """Given a dict for the "m.visibility" config return if the entity should
    be public or not
    """
    vis_type = visibility.get("type")
    if not vis_type:
        return True

    if vis_type not in ("public", "private"):
        raise SynapseError(400, "Synapse only supports 'public'/'private' visibility")
    return vis_type == "public"
