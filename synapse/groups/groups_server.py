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
from synapse.types import UserID, get_domain_from_id


import logging

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

        # Ensure attestations get renewed
        hs.get_groups_attestation_renewer()

    @defer.inlineCallbacks
    def check_group_is_ours(self, group_id, and_exists=False):
        """Check that the group is ours, and optionally if it exists.

        If group does exist then return group.
        """
        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Group not on this server")

        group = yield self.store.get_group(group_id)
        if and_exists and not group:
            raise SynapseError(404, "Unknown group")

        defer.returnValue(group)

    @defer.inlineCallbacks
    def get_group_profile(self, group_id, requester_user_id):
        """Get the group profile as seen by requester_user_id
        """

        yield self.check_group_is_ours(group_id)

        group_description = yield self.store.get_group(group_id)

        if group_description:
            defer.returnValue(group_description)
        else:
            raise SynapseError(404, "Unknown group")

    @defer.inlineCallbacks
    def get_users_in_group(self, group_id, requester_user_id):
        """Get the users in group as seen by requester_user_id
        """

        yield self.check_group_is_ours(group_id, and_exists=True)

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

            if not self.is_mine_id(requester_user_id):
                attestation = yield self.store.get_remote_attestation(group_id, g_user_id)
                if not attestation:
                    continue

                entry["attestation"] = attestation
            else:
                entry["attestation"] = self.attestations.create_attestation(
                    group_id, g_user_id,
                )

            chunk.append(entry)

        # TODO: If admin add lists of users whose attestations have timed out

        defer.returnValue({
            "chunk": chunk,
            "total_user_count_estimate": len(user_results),
        })

    @defer.inlineCallbacks
    def get_rooms_in_group(self, group_id, requester_user_id):
        """Get the rooms in group as seen by requester_user_id
        """

        yield self.check_group_is_ours(group_id, and_exists=True)

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
                with_alias=False, allow_private=True,
            )

            if not entry:
                continue

            if not is_public:
                entry["is_public"] = False

            chunk.append(entry)

        chunk.sort(key=lambda e: -e["num_joined_members"])

        defer.returnValue({
            "chunk": chunk,
            "total_room_count_estimate": len(room_results),
        })

    @defer.inlineCallbacks
    def add_room(self, group_id, requester_user_id, room_id, content):
        """Add room to group
        """

        yield self.check_group_is_ours(group_id, and_exists=True)

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
    def invite_to_group(self, group_id, user_id, requester_user_id, content):
        """Invite user to group
        """

        group = yield self.check_group_is_ours(group_id, and_exists=True)

        is_admin = yield self.store.is_user_admin_in_group(
            group_id, requester_user_id
        )
        if not is_admin:
            raise SynapseError(403, "User is not admin in group")

        # TODO: Check if user knocked
        # TODO: Check if user is already invited

        content = {
            "profile": {
                "name": group["name"],
                "avatar_url": group["avatar_url"],
            },
            "inviter": requester_user_id,
        }

        if self.hs.is_mine_id(user_id):
            raise NotImplementedError()
        else:
            local_attestation = self.attestations.create_attestation(group_id, user_id)
            content.update({
                "attestation": local_attestation,
            })

            res = yield self.transport_client.invite_to_group_notification(
                get_domain_from_id(user_id), group_id, user_id, content
            )

        if res["state"] == "join":
            if not self.hs.is_mine_id(user_id):
                remote_attestation = res["attestation"]

                yield self.attestations.verify_attestation(
                    remote_attestation,
                    user_id=user_id,
                    group_id=group_id,
                )
            else:
                remote_attestation = None

            yield self.store.add_user_to_group(
                group_id, user_id,
                is_admin=False,
                is_public=False,  # TODO
                local_attestation=local_attestation,
                remote_attestation=remote_attestation,
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

    @defer.inlineCallbacks
    def accept_invite(self, group_id, user_id, content):
        """User tries to accept an invite to the group.

        This is different from them asking to join, and so should error if no
        invite exists (and they're not a member of the group)
        """

        yield self.check_group_is_ours(group_id, and_exists=True)

        if not self.store.is_user_invited_to_local_group(group_id, user_id):
            raise SynapseError(403, "User not invited to group")

        if not self.hs.is_mine_id(user_id):
            remote_attestation = content["attestation"]

            yield self.attestations.verify_attestation(
                remote_attestation,
                user_id=user_id,
                group_id=group_id,
            )
        else:
            remote_attestation = None

        local_attestation = self.attestations.create_attestation(group_id, user_id)

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

        yield self.store.add_user_to_group(
            group_id, user_id,
            is_admin=False,
            is_public=is_public,
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
        )

        defer.returnValue({
            "state": "join",
            "attestation": local_attestation,
        })

    @defer.inlineCallbacks
    def knock(self, group_id, user_id, content):
        """A user requests becoming a member of the group
        """
        yield self.check_group_is_ours(group_id, and_exists=True)

        raise NotImplementedError()

    @defer.inlineCallbacks
    def accept_knock(self, group_id, user_id, content):
        """Accept a users knock to the room.

        Errors if the user hasn't knocked, rather than inviting them.
        """

        yield self.check_group_is_ours(group_id, and_exists=True)

        raise NotImplementedError()

    @defer.inlineCallbacks
    def remove_user_from_group(self, group_id, user_id, requester_user_id, content):
        """Remove a user from the group; either a user is leaving or and admin
        kicked htem.
        """

        yield self.check_group_is_ours(group_id, and_exists=True)

        is_kick = False
        if requester_user_id != user_id:
            is_admin = yield self.store.is_user_admin_in_group(
                group_id, requester_user_id
            )
            if not is_admin:
                raise SynapseError(403, "User is not admin in group")

            is_kick = True

        yield self.store.remove_user_from_group(
            group_id, user_id,
        )

        if is_kick:
            if self.hs.is_mine_id(user_id):
                raise NotImplementedError()
            else:
                yield self.transport_client.remove_user_from_group_notification(
                    get_domain_from_id(user_id), group_id, user_id, {}
                )

        defer.returnValue({})

    @defer.inlineCallbacks
    def create_group(self, group_id, user_id, content):
        group = yield self.check_group_is_ours(group_id)

        logger.info("Attempting to create group with ID: %r", group_id)
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
            remote_attestation = content["attestation"]

            yield self.attestations.verify_attestation(
                remote_attestation,
                user_id=user_id,
                group_id=group_id,
            )

            local_attestation = self.attestations.create_attestation(group_id, user_id)
        else:
            local_attestation = None
            remote_attestation = None

        yield self.store.add_user_to_group(
            group_id, user_id,
            is_admin=True,
            is_public=True,  # TODO
            local_attestation=local_attestation,
            remote_attestation=remote_attestation,
        )

        defer.returnValue({
            "group_id": group_id,
        })
