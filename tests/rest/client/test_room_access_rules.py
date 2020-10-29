# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
import json
import random
import string
from typing import Optional

from mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules, Membership, RoomCreationPreset
from synapse.rest import admin
from synapse.rest.client.v1 import directory, login, room
from synapse.third_party_rules.access_rules import (
    ACCESS_RULES_TYPE,
    AccessRules,
    RoomAccessRules,
)
from synapse.types import JsonDict, create_requester

from tests import unittest


class RoomAccessTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        directory.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()

        config["third_party_event_rules"] = {
            "module": "synapse.third_party_rules.access_rules.RoomAccessRules",
            "config": {
                "domains_forbidden_when_restricted": ["forbidden_domain"],
                "id_server": "testis",
            },
        }
        config["trusted_third_party_id_servers"] = ["testis"]

        def send_invite(destination, room_id, event_id, pdu):
            return defer.succeed(pdu)

        def get_json(uri, args={}, headers=None):
            address_domain = args["address"].split("@")[1]
            return defer.succeed({"hs": address_domain})

        def post_json_get_json(uri, post_json, args={}, headers=None):
            token = "".join(random.choice(string.ascii_letters) for _ in range(10))
            return defer.succeed(
                {
                    "token": token,
                    "public_keys": [
                        {
                            "public_key": "serverpublickey",
                            "key_validity_url": "https://testis/pubkey/isvalid",
                        },
                        {
                            "public_key": "phemeralpublickey",
                            "key_validity_url": "https://testis/pubkey/ephemeral/isvalid",
                        },
                    ],
                    "display_name": "f...@b...",
                }
            )

        mock_federation_client = Mock(spec=["send_invite"])
        mock_federation_client.send_invite.side_effect = send_invite

        mock_http_client = Mock(spec=["get_json", "post_json_get_json"],)
        # Mocking the response for /info on the IS API.
        mock_http_client.get_json.side_effect = get_json
        # Mocking the response for /store-invite on the IS API.
        mock_http_client.post_json_get_json.side_effect = post_json_get_json
        self.hs = self.setup_test_homeserver(
            config=config,
            federation_client=mock_federation_client,
            simple_http_client=mock_http_client,
        )

        # TODO: This class does not use a singleton to get it's http client
        # This should be fixed for easier testing
        # https://github.com/matrix-org/synapse-dinsic/issues/26
        self.hs.get_handlers().identity_handler.blacklisting_http_client = (
            mock_http_client
        )

        self.third_party_event_rules = self.hs.get_third_party_event_rules()

        return self.hs

    def prepare(self, reactor, clock, homeserver):
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        self.restricted_room = self.create_room()
        self.unrestricted_room = self.create_room(rule=AccessRules.UNRESTRICTED)
        self.direct_rooms = [
            self.create_room(direct=True),
            self.create_room(direct=True),
            self.create_room(direct=True),
        ]

        self.invitee_id = self.register_user("invitee", "test")
        self.invitee_tok = self.login("invitee", "test")

        self.helper.invite(
            room=self.direct_rooms[0],
            src=self.user_id,
            targ=self.invitee_id,
            tok=self.tok,
        )

    def test_create_room_no_rule(self):
        """Tests that creating a room with no rule will set the default."""
        room_id = self.create_room()
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, AccessRules.RESTRICTED)

    def test_create_room_direct_no_rule(self):
        """Tests that creating a direct room with no rule will set the default."""
        room_id = self.create_room(direct=True)
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, AccessRules.DIRECT)

    def test_create_room_valid_rule(self):
        """Tests that creating a room with a valid rule will set the right."""
        room_id = self.create_room(rule=AccessRules.UNRESTRICTED)
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, AccessRules.UNRESTRICTED)

    def test_create_room_invalid_rule(self):
        """Tests that creating a room with an invalid rule will set fail."""
        self.create_room(rule=AccessRules.DIRECT, expected_code=400)

    def test_create_room_direct_invalid_rule(self):
        """Tests that creating a direct room with an invalid rule will fail.
        """
        self.create_room(direct=True, rule=AccessRules.RESTRICTED, expected_code=400)

    def test_create_room_default_power_level_rules(self):
        """Tests that a room created with no power level overrides instead uses the dinum
        defaults
        """
        room_id = self.create_room(direct=True, rule=AccessRules.DIRECT)
        power_levels = self.helper.get_state(room_id, "m.room.power_levels", self.tok)

        # Inviting another user should require PL50, even in private rooms
        self.assertEqual(power_levels["invite"], 50)
        # Sending arbitrary state events should require PL100
        self.assertEqual(power_levels["state_default"], 100)

    def test_create_room_fails_on_incorrect_power_level_rules(self):
        """Tests that a room created with power levels lower than that required are rejected"""
        modified_power_levels = RoomAccessRules._get_default_power_levels(self.user_id)
        modified_power_levels["invite"] = 0
        modified_power_levels["state_default"] = 50

        self.create_room(
            direct=True,
            rule=AccessRules.DIRECT,
            initial_state=[
                {"type": "m.room.power_levels", "content": modified_power_levels}
            ],
            expected_code=400,
        )

    def test_create_room_with_missing_power_levels_use_default_values(self):
        """
        Tests that a room created with custom power levels, but without defining invite or state_default
        succeeds, but the missing values are replaced with the defaults.
        """

        # Attempt to create a room without defining "invite" or "state_default"
        modified_power_levels = RoomAccessRules._get_default_power_levels(self.user_id)
        del modified_power_levels["invite"]
        del modified_power_levels["state_default"]
        room_id = self.create_room(
            direct=True,
            rule=AccessRules.DIRECT,
            initial_state=[
                {"type": "m.room.power_levels", "content": modified_power_levels}
            ],
        )

        # This should succeed, but the defaults should be put in place instead
        room_power_levels = self.helper.get_state(
            room_id, "m.room.power_levels", self.tok
        )
        self.assertEqual(room_power_levels["invite"], 50)
        self.assertEqual(room_power_levels["state_default"], 100)

        # And now the same test, but using power_levels_content_override instead
        # of initial_state (which takes a slightly different codepath)
        modified_power_levels = RoomAccessRules._get_default_power_levels(self.user_id)
        del modified_power_levels["invite"]
        del modified_power_levels["state_default"]
        room_id = self.create_room(
            direct=True,
            rule=AccessRules.DIRECT,
            power_levels_content_override=modified_power_levels,
        )

        # This should succeed, but the defaults should be put in place instead
        room_power_levels = self.helper.get_state(
            room_id, "m.room.power_levels", self.tok
        )
        self.assertEqual(room_power_levels["invite"], 50)
        self.assertEqual(room_power_levels["state_default"], 100)

    def test_existing_room_can_change_power_levels(self):
        """Tests that a room created with default power levels can have their power levels
        dropped after room creation
        """
        # Creates a room with the default power levels
        room_id = self.create_room(
            direct=True, rule=AccessRules.DIRECT, expected_code=200,
        )

        # Attempt to drop invite and state_default power levels after the fact
        room_power_levels = self.helper.get_state(
            room_id, "m.room.power_levels", self.tok
        )
        room_power_levels["invite"] = 0
        room_power_levels["state_default"] = 50
        self.helper.send_state(
            room_id, "m.room.power_levels", room_power_levels, self.tok
        )

    def test_public_room(self):
        """Tests that it's only possible to have a room listed in the public room list
        if the access rule is restricted.
        """
        # Creating a room with the public_chat preset should succeed and set the access
        # rule to restricted.
        preset_room_id = self.create_room(preset=RoomCreationPreset.PUBLIC_CHAT)
        self.assertEqual(
            self.current_rule_in_room(preset_room_id), AccessRules.RESTRICTED
        )

        # Creating a room with the public join rule in its initial state should succeed
        # and set the access rule to restricted.
        init_state_room_id = self.create_room(
            initial_state=[
                {
                    "type": "m.room.join_rules",
                    "content": {"join_rule": JoinRules.PUBLIC},
                }
            ]
        )
        self.assertEqual(
            self.current_rule_in_room(init_state_room_id), AccessRules.RESTRICTED
        )

        # List preset_room_id in the public room list
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/directory/list/room/%s" % (preset_room_id,),
            {"visibility": "public"},
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        # List init_state_room_id in the public room list
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/directory/list/room/%s" % (init_state_room_id,),
            {"visibility": "public"},
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        # Changing access rule to unrestricted should fail.
        self.change_rule_in_room(
            preset_room_id, AccessRules.UNRESTRICTED, expected_code=403
        )
        self.change_rule_in_room(
            init_state_room_id, AccessRules.UNRESTRICTED, expected_code=403
        )

        # Changing access rule to direct should fail.
        self.change_rule_in_room(preset_room_id, AccessRules.DIRECT, expected_code=403)
        self.change_rule_in_room(
            init_state_room_id, AccessRules.DIRECT, expected_code=403
        )

        # Creating a new room with the public_chat preset and an access rule of direct
        # should fail.
        self.create_room(
            preset=RoomCreationPreset.PUBLIC_CHAT,
            rule=AccessRules.DIRECT,
            expected_code=400,
        )

        # Changing join rule to public in an direct room should fail.
        self.change_join_rule_in_room(
            self.direct_rooms[0], JoinRules.PUBLIC, expected_code=403
        )

    def test_restricted(self):
        """Tests that in restricted mode we're unable to invite users from blacklisted
        servers but can invite other users.

        Also tests that the room can be published to, and removed from, the public room
        list.
        """
        # We can't invite a user from a forbidden HS.
        self.helper.invite(
            room=self.restricted_room,
            src=self.user_id,
            targ="@test:forbidden_domain",
            tok=self.tok,
            expect_code=403,
        )

        # We can invite a user which HS isn't forbidden.
        self.helper.invite(
            room=self.restricted_room,
            src=self.user_id,
            targ="@test:allowed_domain",
            tok=self.tok,
            expect_code=200,
        )

        # We can't send a 3PID invite to an address that is mapped to a forbidden HS.
        self.send_threepid_invite(
            address="test@forbidden_domain",
            room_id=self.restricted_room,
            expected_code=403,
        )

        # We can send a 3PID invite to an address that is mapped to an HS that's not
        # forbidden.
        self.send_threepid_invite(
            address="test@allowed_domain",
            room_id=self.restricted_room,
            expected_code=200,
        )

        # We are allowed to publish the room to the public room list
        url = "/_matrix/client/r0/directory/list/room/%s" % self.restricted_room
        data = {"visibility": "public"}

        request, channel = self.make_request("PUT", url, data, access_token=self.tok)
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        # We are allowed to remove the room from the public room list
        url = "/_matrix/client/r0/directory/list/room/%s" % self.restricted_room
        data = {"visibility": "private"}

        request, channel = self.make_request("PUT", url, data, access_token=self.tok)
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

    def test_direct(self):
        """Tests that, in direct mode, other users than the initial two can't be invited,
        but the following scenario works:
          * invited user joins the room
          * invited user leaves the room
          * room creator re-invites invited user

        Tests that a user from a HS that's in the list of forbidden domains (to use
        in restricted mode) can be invited.

        Tests that the room cannot be published to the public room list.
        """
        not_invited_user = "@not_invited:forbidden_domain"

        # We can't invite a new user to the room.
        self.helper.invite(
            room=self.direct_rooms[0],
            src=self.user_id,
            targ=not_invited_user,
            tok=self.tok,
            expect_code=403,
        )

        # The invited user can join the room.
        self.helper.join(
            room=self.direct_rooms[0],
            user=self.invitee_id,
            tok=self.invitee_tok,
            expect_code=200,
        )

        # The invited user can leave the room.
        self.helper.leave(
            room=self.direct_rooms[0],
            user=self.invitee_id,
            tok=self.invitee_tok,
            expect_code=200,
        )

        # The invited user can be re-invited to the room.
        self.helper.invite(
            room=self.direct_rooms[0],
            src=self.user_id,
            targ=self.invitee_id,
            tok=self.tok,
            expect_code=200,
        )

        # If we're alone in the room and have always been the only member, we can invite
        # someone.
        self.helper.invite(
            room=self.direct_rooms[1],
            src=self.user_id,
            targ=not_invited_user,
            tok=self.tok,
            expect_code=200,
        )

        # Disable the 3pid invite ratelimiter
        burst = self.hs.config.rc_third_party_invite.burst_count
        per_second = self.hs.config.rc_third_party_invite.per_second
        self.hs.config.rc_third_party_invite.burst_count = 10
        self.hs.config.rc_third_party_invite.per_second = 0.1

        # We can't send a 3PID invite to a room that already has two members.
        self.send_threepid_invite(
            address="test@allowed_domain",
            room_id=self.direct_rooms[0],
            expected_code=403,
        )

        # We can't send a 3PID invite to a room that already has a pending invite.
        self.send_threepid_invite(
            address="test@allowed_domain",
            room_id=self.direct_rooms[1],
            expected_code=403,
        )

        # We can send a 3PID invite to a room in which we've always been the only member.
        self.send_threepid_invite(
            address="test@forbidden_domain",
            room_id=self.direct_rooms[2],
            expected_code=200,
        )

        # We can send a 3PID invite to a room in which there's a 3PID invite.
        self.send_threepid_invite(
            address="test@forbidden_domain",
            room_id=self.direct_rooms[2],
            expected_code=403,
        )

        self.hs.config.rc_third_party_invite.burst_count = burst
        self.hs.config.rc_third_party_invite.per_second = per_second

        # We can't publish the room to the public room list
        url = "/_matrix/client/r0/directory/list/room/%s" % self.direct_rooms[0]
        data = {"visibility": "public"}

        request, channel = self.make_request("PUT", url, data, access_token=self.tok)
        self.render(request)
        self.assertEqual(channel.code, 403, channel.result)

    def test_unrestricted(self):
        """Tests that, in unrestricted mode, we can invite whoever we want, but we can
        only change the power level of users that wouldn't be forbidden in restricted
        mode.

        Tests that the room cannot be published to the public room list.
        """
        # We can invite
        self.helper.invite(
            room=self.unrestricted_room,
            src=self.user_id,
            targ="@test:forbidden_domain",
            tok=self.tok,
            expect_code=200,
        )

        self.helper.invite(
            room=self.unrestricted_room,
            src=self.user_id,
            targ="@test:not_forbidden_domain",
            tok=self.tok,
            expect_code=200,
        )

        # We can send a 3PID invite to an address that is mapped to a forbidden HS.
        self.send_threepid_invite(
            address="test@forbidden_domain",
            room_id=self.unrestricted_room,
            expected_code=200,
        )

        # We can send a 3PID invite to an address that is mapped to an HS that's not
        # forbidden.
        self.send_threepid_invite(
            address="test@allowed_domain",
            room_id=self.unrestricted_room,
            expected_code=200,
        )

        # We can send a power level event that doesn't redefine the default PL or set a
        # non-default PL for a user that would be forbidden in restricted mode.
        self.helper.send_state(
            room_id=self.unrestricted_room,
            event_type=EventTypes.PowerLevels,
            body={"users": {self.user_id: 100, "@test:not_forbidden_domain": 10}},
            tok=self.tok,
            expect_code=200,
        )

        # We can't send a power level event that redefines the default PL and doesn't set
        # a non-default PL for a user that would be forbidden in restricted mode.
        self.helper.send_state(
            room_id=self.unrestricted_room,
            event_type=EventTypes.PowerLevels,
            body={
                "users": {self.user_id: 100, "@test:not_forbidden_domain": 10},
                "users_default": 10,
            },
            tok=self.tok,
            expect_code=403,
        )

        # We can't send a power level event that doesn't redefines the default PL but sets
        # a non-default PL for a user that would be forbidden in restricted mode.
        self.helper.send_state(
            room_id=self.unrestricted_room,
            event_type=EventTypes.PowerLevels,
            body={"users": {self.user_id: 100, "@test:forbidden_domain": 10}},
            tok=self.tok,
            expect_code=403,
        )

        # We can't publish the room to the public room list
        url = "/_matrix/client/r0/directory/list/room/%s" % self.unrestricted_room
        data = {"visibility": "public"}

        request, channel = self.make_request("PUT", url, data, access_token=self.tok)
        self.render(request)
        self.assertEqual(channel.code, 403, channel.result)

    def test_change_rules(self):
        """Tests that we can only change the current rule from restricted to
        unrestricted.
        """
        # We can't change the rule from restricted to direct.
        self.change_rule_in_room(
            room_id=self.restricted_room, new_rule=AccessRules.DIRECT, expected_code=403
        )

        # We can change the rule from restricted to unrestricted.
        # Note that this changes self.restricted_room to an unrestricted room
        self.change_rule_in_room(
            room_id=self.restricted_room,
            new_rule=AccessRules.UNRESTRICTED,
            expected_code=200,
        )

        # We can't change the rule from unrestricted to restricted.
        self.change_rule_in_room(
            room_id=self.unrestricted_room,
            new_rule=AccessRules.RESTRICTED,
            expected_code=403,
        )

        # We can't change the rule from unrestricted to direct.
        self.change_rule_in_room(
            room_id=self.unrestricted_room,
            new_rule=AccessRules.DIRECT,
            expected_code=403,
        )

        # We can't change the rule from direct to restricted.
        self.change_rule_in_room(
            room_id=self.direct_rooms[0],
            new_rule=AccessRules.RESTRICTED,
            expected_code=403,
        )

        # We can't change the rule from direct to unrestricted.
        self.change_rule_in_room(
            room_id=self.direct_rooms[0],
            new_rule=AccessRules.UNRESTRICTED,
            expected_code=403,
        )

        # We can't publish a room to the public room list and then change its rule to
        # unrestricted

        # Create a restricted room
        test_room_id = self.create_room(rule=AccessRules.RESTRICTED)

        # Publish the room to the public room list
        url = "/_matrix/client/r0/directory/list/room/%s" % test_room_id
        data = {"visibility": "public"}

        request, channel = self.make_request("PUT", url, data, access_token=self.tok)
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        # Attempt to switch the room to "unrestricted"
        self.change_rule_in_room(
            room_id=test_room_id, new_rule=AccessRules.UNRESTRICTED, expected_code=403
        )

        # Attempt to switch the room to "direct"
        self.change_rule_in_room(
            room_id=test_room_id, new_rule=AccessRules.DIRECT, expected_code=403
        )

    def test_change_room_avatar(self):
        """Tests that changing the room avatar is always allowed unless the room is a
        direct chat, in which case it's forbidden.
        """

        avatar_content = {
            "info": {"h": 398, "mimetype": "image/jpeg", "size": 31037, "w": 394},
            "url": "mxc://example.org/JWEIFJgwEIhweiWJE",
        }

        self.helper.send_state(
            room_id=self.restricted_room,
            event_type=EventTypes.RoomAvatar,
            body=avatar_content,
            tok=self.tok,
            expect_code=200,
        )

        self.helper.send_state(
            room_id=self.unrestricted_room,
            event_type=EventTypes.RoomAvatar,
            body=avatar_content,
            tok=self.tok,
            expect_code=200,
        )

        self.helper.send_state(
            room_id=self.direct_rooms[0],
            event_type=EventTypes.RoomAvatar,
            body=avatar_content,
            tok=self.tok,
            expect_code=403,
        )

    def test_change_room_name(self):
        """Tests that changing the room name is always allowed unless the room is a direct
        chat, in which case it's forbidden.
        """

        name_content = {"name": "My super room"}

        self.helper.send_state(
            room_id=self.restricted_room,
            event_type=EventTypes.Name,
            body=name_content,
            tok=self.tok,
            expect_code=200,
        )

        self.helper.send_state(
            room_id=self.unrestricted_room,
            event_type=EventTypes.Name,
            body=name_content,
            tok=self.tok,
            expect_code=200,
        )

        self.helper.send_state(
            room_id=self.direct_rooms[0],
            event_type=EventTypes.Name,
            body=name_content,
            tok=self.tok,
            expect_code=403,
        )

    def test_change_room_topic(self):
        """Tests that changing the room topic is always allowed unless the room is a
        direct chat, in which case it's forbidden.
        """

        topic_content = {"topic": "Welcome to this room"}

        self.helper.send_state(
            room_id=self.restricted_room,
            event_type=EventTypes.Topic,
            body=topic_content,
            tok=self.tok,
            expect_code=200,
        )

        self.helper.send_state(
            room_id=self.unrestricted_room,
            event_type=EventTypes.Topic,
            body=topic_content,
            tok=self.tok,
            expect_code=200,
        )

        self.helper.send_state(
            room_id=self.direct_rooms[0],
            event_type=EventTypes.Topic,
            body=topic_content,
            tok=self.tok,
            expect_code=403,
        )

    def test_revoke_3pid_invite_direct(self):
        """Tests that revoking a 3PID invite doesn't cause the room access rules module to
        confuse the revokation as a new 3PID invite.
        """
        invite_token = "sometoken"

        invite_body = {
            "display_name": "ker...@exa...",
            "public_keys": [
                {
                    "key_validity_url": "https://validity_url",
                    "public_key": "ta8IQ0u1sp44HVpxYi7dFOdS/bfwDjcy4xLFlfY5KOA",
                },
                {
                    "key_validity_url": "https://validity_url",
                    "public_key": "4_9nzEeDwR5N9s51jPodBiLnqH43A2_g2InVT137t9I",
                },
            ],
            "key_validity_url": "https://validity_url",
            "public_key": "ta8IQ0u1sp44HVpxYi7dFOdS/bfwDjcy4xLFlfY5KOA",
        }

        self.send_state_with_state_key(
            room_id=self.direct_rooms[1],
            event_type=EventTypes.ThirdPartyInvite,
            state_key=invite_token,
            body=invite_body,
            tok=self.tok,
        )

        self.send_state_with_state_key(
            room_id=self.direct_rooms[1],
            event_type=EventTypes.ThirdPartyInvite,
            state_key=invite_token,
            body={},
            tok=self.tok,
        )

        invite_token = "someothertoken"

        self.send_state_with_state_key(
            room_id=self.direct_rooms[1],
            event_type=EventTypes.ThirdPartyInvite,
            state_key=invite_token,
            body=invite_body,
            tok=self.tok,
        )

    def test_check_event_allowed(self):
        """Tests that RoomAccessRules.check_event_allowed behaves accordingly.

        It tests that:
            * forbidden users cannot join restricted rooms.
            * forbidden users can only join unrestricted rooms if they have an invite.
        """
        event_creator = self.hs.get_event_creation_handler()

        # Test that forbidden users cannot join restricted rooms
        requester = create_requester(self.user_id)
        allowed_requester = create_requester("@user:allowed_domain")
        forbidden_requester = create_requester("@user:forbidden_domain")

        # Create a join event for a forbidden user
        forbidden_join_event, forbidden_join_event_context = self.get_success(
            event_creator.create_event(
                forbidden_requester,
                {
                    "type": EventTypes.Member,
                    "room_id": self.restricted_room,
                    "sender": forbidden_requester.user.to_string(),
                    "content": {"membership": Membership.JOIN},
                    "state_key": forbidden_requester.user.to_string(),
                },
            )
        )

        # Create a join event for an allowed user
        allowed_join_event, allowed_join_event_context = self.get_success(
            event_creator.create_event(
                allowed_requester,
                {
                    "type": EventTypes.Member,
                    "room_id": self.restricted_room,
                    "sender": allowed_requester.user.to_string(),
                    "content": {"membership": Membership.JOIN},
                    "state_key": allowed_requester.user.to_string(),
                },
            )
        )

        # Assert a join event from a forbidden user to a restricted room is rejected
        can_join = self.get_success(
            self.third_party_event_rules.check_event_allowed(
                forbidden_join_event, forbidden_join_event_context
            )
        )
        self.assertFalse(can_join)

        # But a join event from an non-forbidden user to a restricted room is allowed
        can_join = self.get_success(
            self.third_party_event_rules.check_event_allowed(
                allowed_join_event, allowed_join_event_context
            )
        )
        self.assertTrue(can_join)

        # Test that forbidden users can only join unrestricted rooms if they have an invite

        # Recreate the forbidden join event for the unrestricted room instead
        forbidden_join_event, forbidden_join_event_context = self.get_success(
            event_creator.create_event(
                forbidden_requester,
                {
                    "type": EventTypes.Member,
                    "room_id": self.unrestricted_room,
                    "sender": forbidden_requester.user.to_string(),
                    "content": {"membership": Membership.JOIN},
                    "state_key": forbidden_requester.user.to_string(),
                },
            )
        )

        # A forbidden user without an invite should not be able to join an unrestricted room
        can_join = self.get_success(
            self.third_party_event_rules.check_event_allowed(
                forbidden_join_event, forbidden_join_event_context
            )
        )
        self.assertFalse(can_join)

        # However, if we then invite this user...
        self.helper.invite(
            room=self.unrestricted_room,
            src=requester.user.to_string(),
            targ=forbidden_requester.user.to_string(),
            tok=self.tok,
        )

        # And create another join event, making sure that its context states it's coming
        # in after the above invite was made...
        forbidden_join_event, forbidden_join_event_context = self.get_success(
            event_creator.create_event(
                forbidden_requester,
                {
                    "type": EventTypes.Member,
                    "room_id": self.unrestricted_room,
                    "sender": forbidden_requester.user.to_string(),
                    "content": {"membership": Membership.JOIN},
                    "state_key": forbidden_requester.user.to_string(),
                },
            )
        )

        # Then the forbidden user should be able to join!
        can_join = self.get_success(
            self.third_party_event_rules.check_event_allowed(
                forbidden_join_event, forbidden_join_event_context
            )
        )
        self.assertTrue(can_join)

    def test_freezing_a_room(self):
        """Tests that the power levels in a room change to prevent new events from
        non-admin users when the last admin of a room leaves.
        """

        def freeze_room_with_id_and_power_levels(
            room_id: str, custom_power_levels_content: Optional[JsonDict] = None,
        ):
            # Invite a user to the room, they join with PL 0
            self.helper.invite(
                room=room_id, src=self.user_id, targ=self.invitee_id, tok=self.tok,
            )

            # Invitee joins the room
            self.helper.join(
                room=room_id, user=self.invitee_id, tok=self.invitee_tok,
            )

            if not custom_power_levels_content:
                # Retrieve the room's current power levels event content
                power_levels = self.helper.get_state(
                    room_id=room_id, event_type="m.room.power_levels", tok=self.tok,
                )
            else:
                power_levels = custom_power_levels_content

                # Override the room's power levels with the given power levels content
                self.helper.send_state(
                    room_id=room_id,
                    event_type="m.room.power_levels",
                    body=custom_power_levels_content,
                    tok=self.tok,
                )

            # Ensure that the invitee leaving the room does not change the power levels
            self.helper.leave(
                room=room_id, user=self.invitee_id, tok=self.invitee_tok,
            )

            # Retrieve the new power levels of the room
            new_power_levels = self.helper.get_state(
                room_id=room_id, event_type="m.room.power_levels", tok=self.tok,
            )

            # Ensure they have not changed
            self.assertDictEqual(power_levels, new_power_levels)

            # Invite the user back again
            self.helper.invite(
                room=room_id, src=self.user_id, targ=self.invitee_id, tok=self.tok,
            )

            # Invitee joins the room
            self.helper.join(
                room=room_id, user=self.invitee_id, tok=self.invitee_tok,
            )

            # Now the admin leaves the room
            self.helper.leave(
                room=room_id, user=self.user_id, tok=self.tok,
            )

            # Check the power levels again
            new_power_levels = self.helper.get_state(
                room_id=room_id, event_type="m.room.power_levels", tok=self.invitee_tok,
            )

            # Ensure that the new power levels prevent anyone but admins from sending
            # certain events
            self.assertEquals(new_power_levels["state_default"], 100)
            self.assertEquals(new_power_levels["events_default"], 100)
            self.assertEquals(new_power_levels["kick"], 100)
            self.assertEquals(new_power_levels["invite"], 100)
            self.assertEquals(new_power_levels["ban"], 100)
            self.assertEquals(new_power_levels["redact"], 100)
            self.assertDictEqual(new_power_levels["events"], {})
            self.assertDictEqual(new_power_levels["users"], {self.user_id: 100})

            # Ensure new users entering the room aren't going to immediately become admins
            self.assertEquals(new_power_levels["users_default"], 0)

        # Test that freezing a room with the default power level state event content works
        room1 = self.create_room()
        freeze_room_with_id_and_power_levels(room1)

        # Test that freezing a room with a power level state event that is missing
        # `state_default` and `event_default` keys behaves as expected
        room2 = self.create_room()
        freeze_room_with_id_and_power_levels(
            room2,
            {
                "ban": 50,
                "events": {
                    "m.room.avatar": 50,
                    "m.room.canonical_alias": 50,
                    "m.room.history_visibility": 100,
                    "m.room.name": 50,
                    "m.room.power_levels": 100,
                },
                "invite": 0,
                "kick": 50,
                "redact": 50,
                "users": {self.user_id: 100},
                "users_default": 0,
                # Explicitly remove `state_default` and `event_default` keys
            },
        )

        # Test that freezing a room with a power level state event that is *additionally*
        # missing `ban`, `invite`, `kick` and `redact` keys behaves as expected
        room3 = self.create_room()
        freeze_room_with_id_and_power_levels(
            room3,
            {
                "events": {
                    "m.room.avatar": 50,
                    "m.room.canonical_alias": 50,
                    "m.room.history_visibility": 100,
                    "m.room.name": 50,
                    "m.room.power_levels": 100,
                },
                "users": {self.user_id: 100},
                "users_default": 0,
                # Explicitly remove `state_default` and `event_default` keys
                # Explicitly remove `ban`, `invite`, `kick` and `redact` keys
            },
        )

    def create_room(
        self,
        direct=False,
        rule=None,
        preset=RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
        initial_state=None,
        power_levels_content_override=None,
        expected_code=200,
    ):
        content = {"is_direct": direct, "preset": preset}

        if rule:
            content["initial_state"] = [
                {"type": ACCESS_RULES_TYPE, "state_key": "", "content": {"rule": rule}}
            ]

        if initial_state:
            if "initial_state" not in content:
                content["initial_state"] = []

            content["initial_state"] += initial_state

        if power_levels_content_override:
            content["power_levels_content_override"] = power_levels_content_override

        request, channel = self.make_request(
            "POST", "/_matrix/client/r0/createRoom", content, access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, expected_code, channel.result)

        if expected_code == 200:
            return channel.json_body["room_id"]

    def current_rule_in_room(self, room_id):
        request, channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/state/%s" % (room_id, ACCESS_RULES_TYPE),
            access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, 200, channel.result)
        return channel.json_body["rule"]

    def change_rule_in_room(self, room_id, new_rule, expected_code=200):
        data = {"rule": new_rule}
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/state/%s" % (room_id, ACCESS_RULES_TYPE),
            json.dumps(data),
            access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, expected_code, channel.result)

    def change_join_rule_in_room(self, room_id, new_join_rule, expected_code=200):
        data = {"join_rule": new_join_rule}
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/state/%s" % (room_id, EventTypes.JoinRules),
            json.dumps(data),
            access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, expected_code, channel.result)

    def send_threepid_invite(self, address, room_id, expected_code=200):
        params = {"id_server": "testis", "medium": "email", "address": address}

        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/%s/invite" % room_id,
            json.dumps(params),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, expected_code, channel.result)

    def send_state_with_state_key(
        self, room_id, event_type, state_key, body, tok, expect_code=200
    ):
        path = "/_matrix/client/r0/rooms/%s/state/%s/%s" % (
            room_id,
            event_type,
            state_key,
        )

        request, channel = self.make_request(
            "PUT", path, json.dumps(body), access_token=tok
        )
        self.render(request)

        self.assertEqual(channel.code, expect_code, channel.result)

        return channel.json_body
