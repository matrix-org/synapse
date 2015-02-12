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
from tests import unittest

from synapse.api.constants import EventTypes
from synapse.events import FrozenEvent
from synapse.handlers.federation import FederationHandler

from mock import NonCallableMock, ANY, Mock

from ..utils import setup_test_homeserver


class FederationTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):

        self.state_handler = NonCallableMock(spec_set=[
            "compute_event_context",
        ])

        self.auth = NonCallableMock(spec_set=[
            "check",
            "check_host_in_room",
        ])

        self.hostname = "test"
        hs = yield setup_test_homeserver(
            self.hostname,
            datastore=NonCallableMock(spec_set=[
                "persist_event",
                "store_room",
                "get_room",
                "get_destination_retry_timings",
                "set_destination_retry_timings",
                "have_events",
            ]),
            resource_for_federation=NonCallableMock(),
            http_client=NonCallableMock(spec_set=[]),
            notifier=NonCallableMock(spec_set=["on_new_room_event"]),
            handlers=NonCallableMock(spec_set=[
                "room_member_handler",
                "federation_handler",
            ]),
            auth=self.auth,
            state_handler=self.state_handler,
            keyring=Mock(),
        )

        self.datastore = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.notifier = hs.get_notifier()
        self.hs = hs

        self.handlers.federation_handler = FederationHandler(self.hs)

    @defer.inlineCallbacks
    def test_msg(self):
        pdu = FrozenEvent({
            "type": EventTypes.Message,
            "room_id": "foo",
            "content": {"msgtype": u"fooo"},
            "origin_server_ts": 0,
            "event_id": "$a:b",
            "user_id":"@a:b",
            "origin": "b",
            "auth_events": [],
            "hashes": {"sha256":"AcLrgtUIqqwaGoHhrEvYG1YLDIsVPYJdSRGhkp3jJp8"},
        })

        self.datastore.persist_event.return_value = defer.succeed(None)
        self.datastore.get_room.return_value = defer.succeed(True)
        self.auth.check_host_in_room.return_value = defer.succeed(True)

        def have_events(event_ids):
            return defer.succeed({})
        self.datastore.have_events.side_effect = have_events

        def annotate(ev, old_state=None):
            context = Mock()
            context.current_state = {}
            context.auth_events = {}
            return defer.succeed(context)
        self.state_handler.compute_event_context.side_effect = annotate

        yield self.handlers.federation_handler.on_receive_pdu(
            "fo", pdu, False
        )

        self.datastore.persist_event.assert_called_once_with(
            ANY,
            is_new_state=True,
            backfilled=False,
            current_state=None,
            context=ANY,
        )

        self.state_handler.compute_event_context.assert_called_once_with(
            ANY, old_state=None,
        )

        self.auth.check.assert_called_once_with(ANY, auth_events={})

        self.notifier.on_new_room_event.assert_called_once_with(
            ANY, extra_users=[]
        )
