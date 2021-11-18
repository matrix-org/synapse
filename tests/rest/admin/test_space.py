# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import Dict, Optional, Tuple, Union

from typing_extensions import Literal

import synapse.rest.admin
from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    JoinRules,
    Membership,
    RestrictedJoinRuleTypes,
    RoomTypes,
)
from synapse.api.room_versions import RoomVersions
from synapse.rest.client import login, room
from synapse.types import JsonDict

from tests import unittest


class RemoveSpaceMemberTestCase(unittest.HomeserverTestCase):
    """Tests removal of a user from a space."""

    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        # Create users
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")
        self.space_owner_user = self.register_user("space_owner", "pass")
        self.space_owner_user_tok = self.login("space_owner", "pass")
        self.target_user = self.register_user("user", "pass")
        self.target_user_tok = self.login("user", "pass")

        # Create a space hierarchy for testing:
        #   space, invite-only
        #    * subspace, restricted
        self.space_id = self._create_space(JoinRules.INVITE)

        # Make the target user a member of the space
        self.helper.invite(
            self.space_id,
            src=self.space_owner_user,
            targ=self.target_user,
            tok=self.space_owner_user_tok,
        )
        self.helper.join(self.space_id, self.target_user, tok=self.target_user_tok)

        self.subspace_id = self._create_space((JoinRules.RESTRICTED, self.space_id))
        self._add_child(self.space_id, self.subspace_id)

    def _add_child(self, space_id: str, room_id: str) -> None:
        """Adds a room to a space."""
        self.helper.send_state(
            space_id,
            event_type=EventTypes.SpaceChild,
            body={"via": [self.hs.hostname]},
            tok=self.space_owner_user_tok,
            state_key=room_id,
        )

    def _create_space(
        self,
        join_rules: Union[
            Literal["public", "invite", "knock"],
            Tuple[Literal["restricted"], str],
        ],
    ) -> str:
        """Creates a space."""
        return self._create_room(
            join_rules,
            extra_content={
                "creation_content": {EventContentFields.ROOM_TYPE: RoomTypes.SPACE}
            },
        )

    def _create_room(
        self,
        join_rules: Union[
            Literal["public", "invite", "knock"],
            Tuple[Literal["restricted"], str],
        ],
        extra_content: Optional[Dict] = None,
    ) -> str:
        """Creates a room."""
        room_id = self.helper.create_room_as(
            self.space_owner_user,
            room_version=RoomVersions.V8.identifier,
            tok=self.space_owner_user_tok,
            extra_content=extra_content,
        )

        if isinstance(join_rules, str):
            self.helper.send_state(
                room_id,
                event_type=EventTypes.JoinRules,
                body={"join_rule": join_rules},
                tok=self.space_owner_user_tok,
            )
        else:
            _, space_id = join_rules
            self.helper.send_state(
                room_id,
                event_type=EventTypes.JoinRules,
                body={
                    "join_rule": JoinRules.RESTRICTED,
                    "allow": [
                        {
                            "type": RestrictedJoinRuleTypes.ROOM_MEMBERSHIP,
                            "room_id": space_id,
                            "via": [self.hs.hostname],
                        }
                    ],
                },
                tok=self.space_owner_user_tok,
            )

        return room_id

    def _remove_from_space(self, user_id: str) -> JsonDict:
        """Removes the given user from the test space."""
        url = f"/_synapse/admin/v1/rooms/{self.space_id}/hierarchy/members/{user_id}"
        channel = self.make_request(
            "DELETE",
            url.encode("ascii"),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, channel.json_body)

        return channel.json_body

    def test_public_space(self) -> None:
        """Tests that the user is removed from the space, even if public."""
        self.helper.send_state(
            self.space_id,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.PUBLIC},
            tok=self.space_owner_user_tok,
        )

        response = self._remove_from_space(self.target_user)

        self.assertCountEqual(response["left"], [self.space_id])
        self.assertEqual(response["failed"], {})

        membership, _ = self.get_success(
            self.store.get_local_current_membership_for_user_in_room(
                self.target_user, self.space_id
            )
        )
        self.assertEqual(membership, Membership.LEAVE)

    def test_public_room(self) -> None:
        """Tests that the user is not removed from public rooms."""
        public_room_id = self._create_room(JoinRules.PUBLIC)
        self._add_child(self.subspace_id, public_room_id)

        self.helper.join(public_room_id, self.target_user, tok=self.target_user_tok)

        response = self._remove_from_space(self.target_user)

        self.assertCountEqual(response["left"], [self.space_id])
        self.assertEqual(response["failed"], {})

        membership, _ = self.get_success(
            self.store.get_local_current_membership_for_user_in_room(
                self.target_user, public_room_id
            )
        )
        self.assertEqual(membership, Membership.JOIN)

    def test_invited(self) -> None:
        """Tests that the user is made to decline invites to rooms in the space."""
        invite_only_room_id = self._create_room(JoinRules.INVITE)
        self._add_child(self.subspace_id, invite_only_room_id)

        self.helper.invite(
            invite_only_room_id,
            src=self.space_owner_user,
            targ=self.target_user,
            tok=self.space_owner_user_tok,
        )

        response = self._remove_from_space(self.target_user)

        self.assertCountEqual(response["left"], [self.space_id, invite_only_room_id])
        self.assertEqual(response["failed"], {})

        membership, _ = self.get_success(
            self.store.get_local_current_membership_for_user_in_room(
                self.target_user, invite_only_room_id
            )
        )
        self.assertEqual(membership, Membership.LEAVE)

    def test_invite_only_room(self) -> None:
        """Tests that the user is made to leave invite-only rooms."""
        invite_only_room_id = self._create_room(JoinRules.INVITE)
        self._add_child(self.subspace_id, invite_only_room_id)

        self.helper.invite(
            invite_only_room_id,
            src=self.space_owner_user,
            targ=self.target_user,
            tok=self.space_owner_user_tok,
        )
        self.helper.join(
            invite_only_room_id, self.target_user, tok=self.target_user_tok
        )

        response = self._remove_from_space(self.target_user)

        self.assertCountEqual(response["left"], [self.space_id, invite_only_room_id])
        self.assertEqual(response["failed"], {})

        membership, _ = self.get_success(
            self.store.get_local_current_membership_for_user_in_room(
                self.target_user, invite_only_room_id
            )
        )
        self.assertEqual(membership, Membership.LEAVE)

    def test_restricted_room(self) -> None:
        """Tests that the user is made to leave restricted rooms."""
        restricted_room_id = self._create_room((JoinRules.RESTRICTED, self.space_id))
        self._add_child(self.subspace_id, restricted_room_id)
        self.helper.join(restricted_room_id, self.target_user, tok=self.target_user_tok)

        response = self._remove_from_space(self.target_user)

        self.assertCountEqual(response["left"], [self.space_id, restricted_room_id])
        self.assertEqual(response["failed"], {})

        membership, _ = self.get_success(
            self.store.get_local_current_membership_for_user_in_room(
                self.target_user, restricted_room_id
            )
        )
        self.assertEqual(membership, Membership.LEAVE)
