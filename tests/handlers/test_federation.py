# Copyright 2014 OpenMarket Ltd
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
from twisted.trial import unittest

from synapse.api.events.room import (
    InviteJoinEvent, MessageEvent, RoomMemberEvent
)
from synapse.api.constants import Membership
from synapse.handlers.federation import FederationHandler
from synapse.server import HomeServer
from synapse.federation.units import Pdu

from mock import NonCallableMock, ANY

import logging

from ..utils import get_mock_call_args

logging.getLogger().addHandler(logging.NullHandler())


class FederationTestCase(unittest.TestCase):

    def setUp(self):
        self.hostname = "test"
        hs = HomeServer(
            self.hostname,
            db_pool=None,
            datastore=NonCallableMock(spec_set=[
                "persist_event",
                "store_room",
                "get_room",
            ]),
            resource_for_federation=NonCallableMock(),
            http_client=NonCallableMock(spec_set=[]),
            notifier=NonCallableMock(spec_set=["on_new_room_event"]),
            handlers=NonCallableMock(spec_set=[
                "room_member_handler",
                "federation_handler",
            ]),
        )

        self.datastore = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.notifier = hs.get_notifier()
        self.hs = hs

        self.handlers.federation_handler = FederationHandler(self.hs)

    @defer.inlineCallbacks
    def test_msg(self):
        pdu = Pdu(
            pdu_type=MessageEvent.TYPE,
            context="foo",
            content={"msgtype": u"fooo"},
            ts=0,
            pdu_id="a",
            origin="b",
        )

        store_id = "ASD"
        self.datastore.persist_event.return_value = defer.succeed(store_id)
        self.datastore.get_room.return_value = defer.succeed(True)

        yield self.handlers.federation_handler.on_receive_pdu(pdu, False)

        self.datastore.persist_event.assert_called_once_with(ANY, False)
        self.notifier.on_new_room_event.assert_called_once_with(ANY)

    @defer.inlineCallbacks
    def test_invite_join_target_this(self):
        room_id = "foo"
        user_id = "@bob:red"

        pdu = Pdu(
            pdu_type=InviteJoinEvent.TYPE,
            user_id=user_id,
            target_host=self.hostname,
            context=room_id,
            content={},
            ts=0,
            pdu_id="a",
            origin="b",
        )

        yield self.handlers.federation_handler.on_receive_pdu(pdu, False)

        mem_handler = self.handlers.room_member_handler
        self.assertEquals(1, mem_handler.change_membership.call_count)
        call_args = get_mock_call_args(
            lambda event, do_auth: None,
            mem_handler.change_membership
        )
        self.assertEquals(True, call_args["do_auth"])

        new_event = call_args["event"]
        self.assertEquals(RoomMemberEvent.TYPE, new_event.type)
        self.assertEquals(room_id, new_event.room_id)
        self.assertEquals(user_id, new_event.state_key)
        self.assertEquals(Membership.JOIN, new_event.membership)

    @defer.inlineCallbacks
    def test_invite_join_target_other(self):
        room_id = "foo"
        user_id = "@bob:red"

        pdu = Pdu(
            pdu_type=InviteJoinEvent.TYPE,
            user_id=user_id,
            state_key="@red:not%s" % self.hostname,
            context=room_id,
            content={},
            ts=0,
            pdu_id="a",
            origin="b",
        )

        yield self.handlers.federation_handler.on_receive_pdu(pdu, False)

        mem_handler = self.handlers.room_member_handler
        self.assertEquals(0, mem_handler.change_membership.call_count)
