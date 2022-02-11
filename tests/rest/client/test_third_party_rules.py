# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import threading
from typing import TYPE_CHECKING, Dict, Optional, Tuple
from unittest.mock import Mock

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.events import EventBase
from synapse.events.third_party_rules import load_legacy_third_party_event_rules
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.types import JsonDict, Requester, StateMap
from synapse.util.frozenutils import unfreeze

from tests import unittest
from tests.test_utils import make_awaitable

if TYPE_CHECKING:
    from synapse.module_api import ModuleApi

thread_local = threading.local()


class LegacyThirdPartyRulesTestModule:
    def __init__(self, config: Dict, module_api: "ModuleApi"):
        # keep a record of the "current" rules module, so that the test can patch
        # it if desired.
        thread_local.rules_module = self
        self.module_api = module_api

    async def on_create_room(
        self, requester: Requester, config: dict, is_requester_admin: bool
    ):
        return True

    async def check_event_allowed(self, event: EventBase, state: StateMap[EventBase]):
        return True

    @staticmethod
    def parse_config(config):
        return config


class LegacyDenyNewRooms(LegacyThirdPartyRulesTestModule):
    def __init__(self, config: Dict, module_api: "ModuleApi"):
        super().__init__(config, module_api)

    def on_create_room(
        self, requester: Requester, config: dict, is_requester_admin: bool
    ):
        return False


class LegacyChangeEvents(LegacyThirdPartyRulesTestModule):
    def __init__(self, config: Dict, module_api: "ModuleApi"):
        super().__init__(config, module_api)

    async def check_event_allowed(self, event: EventBase, state: StateMap[EventBase]):
        d = event.get_dict()
        content = unfreeze(event.content)
        content["foo"] = "bar"
        d["content"] = content
        return d


class ThirdPartyRulesTestCase(unittest.FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()

        load_legacy_third_party_event_rules(hs)

        # We're not going to be properly signing events as our remote homeserver is fake,
        # therefore disable event signature checks.
        # Note that these checks are not relevant to this test case.

        # Have this homeserver auto-approve all event signature checking.
        async def approve_all_signature_checking(_, pdu):
            return pdu

        hs.get_federation_server()._check_sigs_and_hash = approve_all_signature_checking

        # Have this homeserver skip event auth checks. This is necessary due to
        # event auth checks ensuring that events were signed by the sender's homeserver.
        async def _check_event_auth(origin, event, context, *args, **kwargs):
            return context

        hs.get_federation_event_handler()._check_event_auth = _check_event_auth

        return hs

    def prepare(self, reactor, clock, homeserver):
        super().prepare(reactor, clock, homeserver)
        # Create some users and a room to play with during the tests
        self.user_id = self.register_user("kermit", "monkey")
        self.invitee = self.register_user("invitee", "hackme")
        self.tok = self.login("kermit", "monkey")

        # Some tests might prevent room creation on purpose.
        try:
            self.room_id = self.helper.create_room_as(self.user_id, tok=self.tok)
        except Exception:
            pass

    def test_third_party_rules(self):
        """Tests that a forbidden event is forbidden from being sent, but an allowed one
        can be sent.
        """
        # patch the rules module with a Mock which will return False for some event
        # types
        async def check(ev, state):
            return ev.type != "foo.bar.forbidden", None

        callback = Mock(spec=[], side_effect=check)
        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [
            callback
        ]

        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.allowed/1" % self.room_id,
            {},
            access_token=self.tok,
        )
        self.assertEquals(channel.result["code"], b"200", channel.result)

        callback.assert_called_once()

        # there should be various state events in the state arg: do some basic checks
        state_arg = callback.call_args[0][1]
        for k in (("m.room.create", ""), ("m.room.member", self.user_id)):
            self.assertIn(k, state_arg)
            ev = state_arg[k]
            self.assertEqual(ev.type, k[0])
            self.assertEqual(ev.state_key, k[1])

        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.forbidden/2" % self.room_id,
            {},
            access_token=self.tok,
        )
        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_third_party_rules_workaround_synapse_errors_pass_through(self):
        """
        Tests that the workaround introduced by https://github.com/matrix-org/synapse/pull/11042
        is functional: that SynapseErrors are passed through from check_event_allowed
        and bubble up to the web resource.

        NEW MODULES SHOULD NOT MAKE USE OF THIS WORKAROUND!
        This is a temporary workaround!
        """

        class NastyHackException(SynapseError):
            def error_dict(self):
                """
                This overrides SynapseError's `error_dict` to nastily inject
                JSON into the error response.
                """
                result = super().error_dict()
                result["nasty"] = "very"
                return result

        # add a callback that will raise our hacky exception
        async def check(ev, state) -> Tuple[bool, Optional[JsonDict]]:
            raise NastyHackException(429, "message")

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [check]

        # Make a request
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/foo.bar.forbidden/2" % self.room_id,
            {},
            access_token=self.tok,
        )
        # Check the error code
        self.assertEquals(channel.result["code"], b"429", channel.result)
        # Check the JSON body has had the `nasty` key injected
        self.assertEqual(
            channel.json_body,
            {"errcode": "M_UNKNOWN", "error": "message", "nasty": "very"},
        )

    def test_cannot_modify_event(self):
        """cannot accidentally modify an event before it is persisted"""

        # first patch the event checker so that it will try to modify the event
        async def check(ev: EventBase, state):
            ev.content = {"x": "y"}
            return True, None

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [check]

        # now send the event
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {"x": "x"},
            access_token=self.tok,
        )
        # Because check_event_allowed raises an exception, it leads to a
        # 500 Internal Server Error
        self.assertEqual(channel.code, 500, channel.result)

    def test_modify_event(self):
        """The module can return a modified version of the event"""
        # first patch the event checker so that it will modify the event
        async def check(ev: EventBase, state):
            d = ev.get_dict()
            d["content"] = {"x": "y"}
            return True, d

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [check]

        # now send the event
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {"x": "x"},
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        event_id = channel.json_body["event_id"]

        # ... and check that it got modified
        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["x"], "y")

    def test_message_edit(self):
        """Ensure that the module doesn't cause issues with edited messages."""
        # first patch the event checker so that it will modify the event
        async def check(ev: EventBase, state):
            d = ev.get_dict()
            d["content"] = {
                "msgtype": "m.text",
                "body": d["content"]["body"].upper(),
            }
            return True, d

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [check]

        # Send an event, then edit it.
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/modifyme/1" % self.room_id,
            {
                "msgtype": "m.text",
                "body": "Original body",
            },
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        orig_event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/m.room.message/2" % self.room_id,
            {
                "m.new_content": {"msgtype": "m.text", "body": "Edited body"},
                "m.relates_to": {
                    "rel_type": "m.replace",
                    "event_id": orig_event_id,
                },
                "msgtype": "m.text",
                "body": "Edited body",
            },
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        edited_event_id = channel.json_body["event_id"]

        # ... and check that they both got modified
        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, orig_event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["body"], "ORIGINAL BODY")

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, edited_event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)
        ev = channel.json_body
        self.assertEqual(ev["content"]["body"], "EDITED BODY")

    def test_send_event(self):
        """Tests that a module can send an event into a room via the module api"""
        content = {
            "msgtype": "m.text",
            "body": "Hello!",
        }
        event_dict = {
            "room_id": self.room_id,
            "type": "m.room.message",
            "content": content,
            "sender": self.user_id,
        }
        event: EventBase = self.get_success(
            self.hs.get_module_api().create_and_send_event_into_room(event_dict)
        )

        self.assertEquals(event.sender, self.user_id)
        self.assertEquals(event.room_id, self.room_id)
        self.assertEquals(event.type, "m.room.message")
        self.assertEquals(event.content, content)

    @unittest.override_config(
        {
            "third_party_event_rules": {
                "module": __name__ + ".LegacyChangeEvents",
                "config": {},
            }
        }
    )
    def test_legacy_check_event_allowed(self):
        """Tests that the wrapper for legacy check_event_allowed callbacks works
        correctly.
        """
        channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/send/m.room.message/1" % self.room_id,
            {
                "msgtype": "m.text",
                "body": "Original body",
            },
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)

        event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            "/_matrix/client/r0/rooms/%s/event/%s" % (self.room_id, event_id),
            access_token=self.tok,
        )
        self.assertEqual(channel.result["code"], b"200", channel.result)

        self.assertIn("foo", channel.json_body["content"].keys())
        self.assertEqual(channel.json_body["content"]["foo"], "bar")

    @unittest.override_config(
        {
            "third_party_event_rules": {
                "module": __name__ + ".LegacyDenyNewRooms",
                "config": {},
            }
        }
    )
    def test_legacy_on_create_room(self):
        """Tests that the wrapper for legacy on_create_room callbacks works
        correctly.
        """
        self.helper.create_room_as(self.user_id, tok=self.tok, expect_code=403)

    def test_sent_event_end_up_in_room_state(self):
        """Tests that a state event sent by a module while processing another state event
        doesn't get dropped from the state of the room. This is to guard against a bug
        where Synapse has been observed doing so, see https://github.com/matrix-org/synapse/issues/10830
        """
        event_type = "org.matrix.test_state"

        # This content will be updated later on, and since we actually use a reference on
        # the dict it does the right thing. It's a bit hacky but a handy way of making
        # sure the state actually gets updated.
        event_content = {"i": -1}

        api = self.hs.get_module_api()

        # Define a callback that sends a custom event on power levels update.
        async def test_fn(event: EventBase, state_events):
            if event.is_state and event.type == EventTypes.PowerLevels:
                await api.create_and_send_event_into_room(
                    {
                        "room_id": event.room_id,
                        "sender": event.sender,
                        "type": event_type,
                        "content": event_content,
                        "state_key": "",
                    }
                )
            return True, None

        self.hs.get_third_party_event_rules()._check_event_allowed_callbacks = [test_fn]

        # Sometimes the bug might not happen the first time the event type is added
        # to the state but might happen when an event updates the state of the room for
        # that type, so we test updating the state several times.
        for i in range(5):
            # Update the content of the custom state event to be sent by the callback.
            event_content["i"] = i

            # Update the room's power levels with a different value each time so Synapse
            # doesn't consider an update redundant.
            self._update_power_levels(event_default=i)

            # Check that the new event made it to the room's state.
            channel = self.make_request(
                method="GET",
                path="/rooms/" + self.room_id + "/state/" + event_type,
                access_token=self.tok,
            )

            self.assertEqual(channel.code, 200)
            self.assertEqual(channel.json_body["i"], i)

    def test_on_new_event(self):
        """Test that the on_new_event callback is called on new events"""
        on_new_event = Mock(make_awaitable(None))
        self.hs.get_third_party_event_rules()._on_new_event_callbacks.append(
            on_new_event
        )

        # Send a message event to the room and check that the callback is called.
        self.helper.send(room_id=self.room_id, tok=self.tok)
        self.assertEqual(on_new_event.call_count, 1)

        # Check that the callback is also called on membership updates.
        self.helper.invite(
            room=self.room_id,
            src=self.user_id,
            targ=self.invitee,
            tok=self.tok,
        )

        self.assertEqual(on_new_event.call_count, 2)

        args, _ = on_new_event.call_args

        self.assertEqual(args[0].membership, Membership.INVITE)
        self.assertEqual(args[0].state_key, self.invitee)

        # Check that the invitee's membership is correct in the state that's passed down
        # to the callback.
        self.assertEqual(
            args[1][(EventTypes.Member, self.invitee)].membership,
            Membership.INVITE,
        )

        # Send an event over federation and check that the callback is also called.
        self._send_event_over_federation()
        self.assertEqual(on_new_event.call_count, 3)

    def _send_event_over_federation(self) -> None:
        """Send a dummy event over federation and check that the request succeeds."""
        body = {
            "pdus": [
                {
                    "sender": self.user_id,
                    "type": EventTypes.Message,
                    "state_key": "",
                    "content": {"body": "hello world", "msgtype": "m.text"},
                    "room_id": self.room_id,
                    "depth": 0,
                    "origin_server_ts": self.clock.time_msec(),
                    "prev_events": [],
                    "auth_events": [],
                    "signatures": {},
                    "unsigned": {},
                }
            ],
        }

        channel = self.make_signed_federation_request(
            method="PUT",
            path="/_matrix/federation/v1/send/1",
            content=body,
        )

        self.assertEqual(channel.code, 200, channel.result)

    def _update_power_levels(self, event_default: int = 0):
        """Updates the room's power levels.

        Args:
            event_default: Value to use for 'events_default'.
        """
        self.helper.send_state(
            room_id=self.room_id,
            event_type=EventTypes.PowerLevels,
            body={
                "ban": 50,
                "events": {
                    "m.room.avatar": 50,
                    "m.room.canonical_alias": 50,
                    "m.room.encryption": 100,
                    "m.room.history_visibility": 100,
                    "m.room.name": 50,
                    "m.room.power_levels": 100,
                    "m.room.server_acl": 100,
                    "m.room.tombstone": 100,
                },
                "events_default": event_default,
                "invite": 0,
                "kick": 50,
                "redact": 50,
                "state_default": 50,
                "users": {self.user_id: 100},
                "users_default": 0,
            },
            tok=self.tok,
        )
