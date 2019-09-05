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

from mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules, RoomCreationPreset
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.third_party_rules.access_rules import (
    ACCESS_RULE_DIRECT,
    ACCESS_RULE_RESTRICTED,
    ACCESS_RULE_UNRESTRICTED,
    ACCESS_RULES_TYPE,
)

from tests import unittest


class RoomAccessTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()

        config["third_party_event_rules"] = {
            "module": "synapse.third_party_rules.access_rules.RoomAccessRules",
            "config": {
                "domains_forbidden_when_restricted": [
                    "forbidden_domain"
                ],
                "id_server": "testis",
            }
        }
        config["trusted_third_party_id_servers"] = [
            "testis",
        ]

        def send_invite(destination, room_id, event_id, pdu):
            return defer.succeed(pdu)

        def get_json(uri, args={}, headers=None):
            address_domain = args["address"].split("@")[1]
            return defer.succeed({"hs": address_domain})

        def post_urlencoded_get_json(uri, args={}, headers=None):
            token = ''.join(random.choice(string.ascii_letters) for _ in range(10))
            return defer.succeed({
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
            })

        mock_federation_client = Mock(spec=[
            "send_invite",
        ])
        mock_federation_client.send_invite.side_effect = send_invite

        mock_http_client = Mock(spec=[
            "get_json",
            "post_urlencoded_get_json"
        ])
        # Mocking the response for /info on the IS API.
        mock_http_client.get_json.side_effect = get_json
        # Mocking the response for /store-invite on the IS API.
        mock_http_client.post_urlencoded_get_json.side_effect = post_urlencoded_get_json
        self.hs = self.setup_test_homeserver(
            config=config,
            federation_client=mock_federation_client,
            simple_http_client=mock_http_client,
        )

        return self.hs

    def prepare(self, reactor, clock, homeserver):
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        self.restricted_room = self.create_room()
        self.unrestricted_room = self.create_room(rule=ACCESS_RULE_UNRESTRICTED)
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
        """Tests that creating a room with no rule will set the default value."""
        room_id = self.create_room()
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, ACCESS_RULE_RESTRICTED)

    def test_create_room_direct_no_rule(self):
        """Tests that creating a direct room with no rule will set the default value."""
        room_id = self.create_room(direct=True)
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, ACCESS_RULE_DIRECT)

    def test_create_room_valid_rule(self):
        """Tests that creating a room with a valid rule will set the right value."""
        room_id = self.create_room(rule=ACCESS_RULE_UNRESTRICTED)
        rule = self.current_rule_in_room(room_id)

        self.assertEqual(rule, ACCESS_RULE_UNRESTRICTED)

    def test_create_room_invalid_rule(self):
        """Tests that creating a room with an invalid rule will set fail."""
        self.create_room(rule=ACCESS_RULE_DIRECT, expected_code=400)

    def test_create_room_direct_invalid_rule(self):
        """Tests that creating a direct room with an invalid rule will fail.
        """
        self.create_room(direct=True, rule=ACCESS_RULE_RESTRICTED, expected_code=400)

    def test_public_room(self):
        """Tests that it's not possible to have a room with the public join rule and an
        access rule that's not restricted.
        """
        # Creating a room with the public_chat preset should succeed and set the access
        # rule to restricted.
        preset_room_id = self.create_room(preset=RoomCreationPreset.PUBLIC_CHAT)
        self.assertEqual(
            self.current_rule_in_room(preset_room_id), ACCESS_RULE_RESTRICTED,
        )

        # Creating a room with the public join rule in its initial state should succeed
        # and set the access rule to restricted.
        init_state_room_id = self.create_room(initial_state=[{
            "type": "m.room.join_rules",
            "content": {
                "join_rule": JoinRules.PUBLIC,
            },
        }])
        self.assertEqual(
            self.current_rule_in_room(init_state_room_id), ACCESS_RULE_RESTRICTED,
        )

        # Changing access rule to unrestricted should fail.
        self.change_rule_in_room(
            preset_room_id, ACCESS_RULE_UNRESTRICTED, expected_code=403,
        )
        self.change_rule_in_room(
            init_state_room_id, ACCESS_RULE_UNRESTRICTED, expected_code=403,
        )

        # Changing access rule to direct should fail.
        self.change_rule_in_room(
            preset_room_id, ACCESS_RULE_DIRECT, expected_code=403,
        )
        self.change_rule_in_room(
            init_state_room_id, ACCESS_RULE_DIRECT, expected_code=403,
        )

        # Changing join rule to public in an unrestricted room should fail.
        self.change_join_rule_in_room(
            self.unrestricted_room, JoinRules.PUBLIC, expected_code=403,
        )
        # Changing join rule to public in an direct room should fail.
        self.change_join_rule_in_room(
            self.direct_rooms[0], JoinRules.PUBLIC, expected_code=403,
        )

        # Creating a new room with the public_chat preset and an access rule that isn't
        # restricted should fail.
        self.create_room(
            preset=RoomCreationPreset.PUBLIC_CHAT, rule=ACCESS_RULE_UNRESTRICTED,
            expected_code=400,
        )
        self.create_room(
            preset=RoomCreationPreset.PUBLIC_CHAT, rule=ACCESS_RULE_DIRECT,
            expected_code=400,
        )

        # Creating a room with the public join rule in its initial state and an access
        # rule that isn't restricted should fail.
        self.create_room(
            initial_state=[{
                "type": "m.room.join_rules",
                "content": {
                    "join_rule": JoinRules.PUBLIC,
                },
            }], rule=ACCESS_RULE_UNRESTRICTED, expected_code=400,
        )
        self.create_room(
            initial_state=[{
                "type": "m.room.join_rules",
                "content": {
                    "join_rule": JoinRules.PUBLIC,
                },
            }], rule=ACCESS_RULE_DIRECT, expected_code=400,
        )

    def test_restricted(self):
        """Tests that in restricted mode we're unable to invite users from blacklisted
        servers but can invite other users.
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

    def test_direct(self):
        """Tests that, in direct mode, other users than the initial two can't be invited,
        but the following scenario works:
          * invited user joins the room
          * invited user leaves the room
          * room creator re-invites invited user
        Also tests that a user from a HS that's in the list of forbidden domains (to use
        in restricted mode) can be invited.
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

    def test_unrestricted(self):
        """Tests that, in unrestricted mode, we can invite whoever we want, but we can
        only change the power level of users that wouldn't be forbidden in restricted
        mode.
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
            body={
                "users": {
                    self.user_id: 100,
                    "@test:not_forbidden_domain": 10,
                },
            },
            tok=self.tok,
            expect_code=200,
        )

        # We can't send a power level event that redefines the default PL and doesn't set
        # a non-default PL for a user that would be forbidden in restricted mode.
        self.helper.send_state(
            room_id=self.unrestricted_room,
            event_type=EventTypes.PowerLevels,
            body={
                "users": {
                    self.user_id: 100,
                    "@test:not_forbidden_domain": 10,
                },
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
            body={
                "users": {
                    self.user_id: 100,
                    "@test:forbidden_domain": 10,
                },
            },
            tok=self.tok,
            expect_code=403,
        )

    def test_change_rules(self):
        """Tests that we can only change the current rule from restricted to
        unrestricted.
        """
        # We can change the rule from restricted to unrestricted.
        self.change_rule_in_room(
            room_id=self.restricted_room,
            new_rule=ACCESS_RULE_UNRESTRICTED,
            expected_code=200,
        )

        # We can't change the rule from restricted to direct.
        self.change_rule_in_room(
            room_id=self.restricted_room,
            new_rule=ACCESS_RULE_DIRECT,
            expected_code=403,
        )

        # We can't change the rule from unrestricted to restricted.
        self.change_rule_in_room(
            room_id=self.unrestricted_room,
            new_rule=ACCESS_RULE_RESTRICTED,
            expected_code=403,
        )

        # We can't change the rule from unrestricted to direct.
        self.change_rule_in_room(
            room_id=self.unrestricted_room,
            new_rule=ACCESS_RULE_DIRECT,
            expected_code=403,
        )

        # We can't change the rule from direct to restricted.
        self.change_rule_in_room(
            room_id=self.direct_rooms[0],
            new_rule=ACCESS_RULE_RESTRICTED,
            expected_code=403,
        )

        # We can't change the rule from direct to unrestricted.
        self.change_rule_in_room(
            room_id=self.direct_rooms[0],
            new_rule=ACCESS_RULE_UNRESTRICTED,
            expected_code=403,
        )

    def test_change_room_avatar(self):
        """Tests that changing the room avatar is always allowed unless the room is a
        direct chat, in which case it's forbidden.
        """

        avatar_content = {
            "info": {
                "h": 398,
                "mimetype": "image/jpeg",
                "size": 31037,
                "w": 394
            },
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

        name_content = {
            "name": "My super room",
        }

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

        topic_content = {
            "topic": "Welcome to this room",
        }

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

    def create_room(
        self, direct=False, rule=None, preset=RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
        initial_state=None, expected_code=200,
    ):
        content = {
            "is_direct": direct,
            "preset": preset,
        }

        if rule:
            content["initial_state"] = [{
                "type": ACCESS_RULES_TYPE,
                "state_key": "",
                "content": {
                    "rule": rule,
                }
            }]

        if initial_state:
            if "initial_state" not in content:
                content["initial_state"] = []

            content["initial_state"] += initial_state

        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/createRoom",
            json.dumps(content),
            access_token=self.tok,
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
        data = {
            "rule": new_rule,
        }
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/state/%s" % (room_id, ACCESS_RULES_TYPE),
            json.dumps(data),
            access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, expected_code, channel.result)

    def change_join_rule_in_room(self, room_id, new_join_rule, expected_code=200):
        data = {
            "join_rule": new_join_rule,
        }
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/state/%s" % (room_id, EventTypes.JoinRules),
            json.dumps(data),
            access_token=self.tok,
        )
        self.render(request)

        self.assertEqual(channel.code, expected_code, channel.result)

    def send_threepid_invite(self, address, room_id, expected_code=200):
        params = {
            "id_server": "testis",
            "medium": "email",
            "address": address,
        }

        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/%s/invite" % room_id,
            json.dumps(params),
            access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.code, expected_code, channel.result)
