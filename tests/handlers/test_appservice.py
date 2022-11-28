# Copyright 2015-2021 The Matrix.org Foundation C.I.C.
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

from typing import Dict, Iterable, List, Optional
from unittest.mock import Mock

from parameterized import parameterized

from twisted.internet import defer
from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
import synapse.storage
from synapse.api.constants import EduTypes, EventTypes
from synapse.appservice import (
    ApplicationService,
    TransactionOneTimeKeyCounts,
    TransactionUnusedFallbackKeys,
)
from synapse.handlers.appservice import ApplicationServicesHandler
from synapse.rest.client import login, receipts, register, room, sendtodevice
from synapse.server import HomeServer
from synapse.types import RoomStreamToken
from synapse.util import Clock
from synapse.util.stringutils import random_string

from tests import unittest
from tests.test_utils import event_injection, make_awaitable, simple_async_mock
from tests.unittest import override_config
from tests.utils import MockClock


class AppServiceHandlerTestCase(unittest.TestCase):
    """Tests the ApplicationServicesHandler."""

    def setUp(self):
        self.mock_store = Mock()
        self.mock_as_api = Mock()
        self.mock_scheduler = Mock()
        hs = Mock()
        hs.get_datastores.return_value = Mock(main=self.mock_store)
        self.mock_store.get_appservice_last_pos.return_value = make_awaitable(None)
        self.mock_store.set_appservice_last_pos.return_value = make_awaitable(None)
        self.mock_store.set_appservice_stream_type_pos.return_value = make_awaitable(
            None
        )
        hs.get_application_service_api.return_value = self.mock_as_api
        hs.get_application_service_scheduler.return_value = self.mock_scheduler
        hs.get_clock.return_value = MockClock()
        self.handler = ApplicationServicesHandler(hs)
        self.event_source = hs.get_event_sources()

    def test_notify_interested_services(self):
        interested_service = self._mkservice(is_interested_in_event=True)
        services = [
            self._mkservice(is_interested_in_event=False),
            interested_service,
            self._mkservice(is_interested_in_event=False),
        ]

        self.mock_as_api.query_user.return_value = make_awaitable(True)
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_user_by_id.return_value = make_awaitable([])

        event = Mock(
            sender="@someone:anywhere", type="m.room.message", room_id="!foo:bar"
        )
        self.mock_store.get_all_new_event_ids_stream.side_effect = [
            make_awaitable((0, {})),
            make_awaitable((1, {event.event_id: 0})),
        ]
        self.mock_store.get_events_as_list.side_effect = [
            make_awaitable([]),
            make_awaitable([event]),
        ]
        self.handler.notify_interested_services(RoomStreamToken(None, 1))

        self.mock_scheduler.enqueue_for_appservice.assert_called_once_with(
            interested_service, events=[event]
        )

    def test_query_user_exists_unknown_user(self):
        user_id = "@someone:anywhere"
        services = [self._mkservice(is_interested_in_event=True)]
        services[0].is_interested_in_user.return_value = True
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_user_by_id.return_value = make_awaitable(None)

        event = Mock(sender=user_id, type="m.room.message", room_id="!foo:bar")
        self.mock_as_api.query_user.return_value = make_awaitable(True)
        self.mock_store.get_all_new_event_ids_stream.side_effect = [
            make_awaitable((0, {event.event_id: 0})),
        ]
        self.mock_store.get_events_as_list.side_effect = [make_awaitable([event])]
        self.handler.notify_interested_services(RoomStreamToken(None, 0))

        self.mock_as_api.query_user.assert_called_once_with(services[0], user_id)

    def test_query_user_exists_known_user(self):
        user_id = "@someone:anywhere"
        services = [self._mkservice(is_interested_in_event=True)]
        services[0].is_interested_in_user.return_value = True
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_user_by_id.return_value = make_awaitable({"name": user_id})

        event = Mock(sender=user_id, type="m.room.message", room_id="!foo:bar")
        self.mock_as_api.query_user.return_value = make_awaitable(True)
        self.mock_store.get_all_new_event_ids_stream.side_effect = [
            make_awaitable((0, [event], {event.event_id: 0})),
        ]

        self.handler.notify_interested_services(RoomStreamToken(None, 0))

        self.assertFalse(
            self.mock_as_api.query_user.called,
            "query_user called when it shouldn't have been.",
        )

    def test_query_room_alias_exists(self):
        room_alias_str = "#foo:bar"
        room_alias = Mock()
        room_alias.to_string.return_value = room_alias_str

        room_id = "!alpha:bet"
        servers = ["aperture"]
        interested_service = self._mkservice_alias(is_room_alias_in_namespace=True)
        services = [
            self._mkservice_alias(is_room_alias_in_namespace=False),
            interested_service,
            self._mkservice_alias(is_room_alias_in_namespace=False),
        ]

        self.mock_as_api.query_alias.return_value = make_awaitable(True)
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_association_from_room_alias.return_value = make_awaitable(
            Mock(room_id=room_id, servers=servers)
        )

        result = self.successResultOf(
            defer.ensureDeferred(self.handler.query_room_alias_exists(room_alias))
        )

        self.mock_as_api.query_alias.assert_called_once_with(
            interested_service, room_alias_str
        )
        self.assertEqual(result.room_id, room_id)
        self.assertEqual(result.servers, servers)

    def test_get_3pe_protocols_no_appservices(self):
        self.mock_store.get_app_services.return_value = []
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols("my-protocol"))
        )
        self.mock_as_api.get_3pe_protocol.assert_not_called()
        self.assertEqual(response, {})

    def test_get_3pe_protocols_no_protocols(self):
        service = self._mkservice(False, [])
        self.mock_store.get_app_services.return_value = [service]
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols())
        )
        self.mock_as_api.get_3pe_protocol.assert_not_called()
        self.assertEqual(response, {})

    def test_get_3pe_protocols_protocol_no_response(self):
        service = self._mkservice(False, ["my-protocol"])
        self.mock_store.get_app_services.return_value = [service]
        self.mock_as_api.get_3pe_protocol.return_value = make_awaitable(None)
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols())
        )
        self.mock_as_api.get_3pe_protocol.assert_called_once_with(
            service, "my-protocol"
        )
        self.assertEqual(response, {})

    def test_get_3pe_protocols_select_one_protocol(self):
        service = self._mkservice(False, ["my-protocol"])
        self.mock_store.get_app_services.return_value = [service]
        self.mock_as_api.get_3pe_protocol.return_value = make_awaitable(
            {"x-protocol-data": 42, "instances": []}
        )
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols("my-protocol"))
        )
        self.mock_as_api.get_3pe_protocol.assert_called_once_with(
            service, "my-protocol"
        )
        self.assertEqual(
            response, {"my-protocol": {"x-protocol-data": 42, "instances": []}}
        )

    def test_get_3pe_protocols_one_protocol(self):
        service = self._mkservice(False, ["my-protocol"])
        self.mock_store.get_app_services.return_value = [service]
        self.mock_as_api.get_3pe_protocol.return_value = make_awaitable(
            {"x-protocol-data": 42, "instances": []}
        )
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols())
        )
        self.mock_as_api.get_3pe_protocol.assert_called_once_with(
            service, "my-protocol"
        )
        self.assertEqual(
            response, {"my-protocol": {"x-protocol-data": 42, "instances": []}}
        )

    def test_get_3pe_protocols_multiple_protocol(self):
        service_one = self._mkservice(False, ["my-protocol"])
        service_two = self._mkservice(False, ["other-protocol"])
        self.mock_store.get_app_services.return_value = [service_one, service_two]
        self.mock_as_api.get_3pe_protocol.return_value = make_awaitable(
            {"x-protocol-data": 42, "instances": []}
        )
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols())
        )
        self.mock_as_api.get_3pe_protocol.assert_called()
        self.assertEqual(
            response,
            {
                "my-protocol": {"x-protocol-data": 42, "instances": []},
                "other-protocol": {"x-protocol-data": 42, "instances": []},
            },
        )

    def test_get_3pe_protocols_multiple_info(self):
        service_one = self._mkservice(False, ["my-protocol"])
        service_two = self._mkservice(False, ["my-protocol"])

        async def get_3pe_protocol(service, unusedProtocol):
            if service == service_one:
                return {
                    "x-protocol-data": 42,
                    "instances": [{"desc": "Alice's service"}],
                }
            if service == service_two:
                return {
                    "x-protocol-data": 36,
                    "x-not-used": 45,
                    "instances": [{"desc": "Bob's service"}],
                }
            raise Exception("Unexpected service")

        self.mock_store.get_app_services.return_value = [service_one, service_two]
        self.mock_as_api.get_3pe_protocol = get_3pe_protocol
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols())
        )
        # It's expected that the second service's data doesn't appear in the response
        self.assertEqual(
            response,
            {
                "my-protocol": {
                    "x-protocol-data": 42,
                    "instances": [
                        {
                            "desc": "Alice's service",
                        },
                        {"desc": "Bob's service"},
                    ],
                },
            },
        )

    def test_notify_interested_services_ephemeral(self):
        """
        Test sending ephemeral events to the appservice handler are scheduled
        to be pushed out to interested appservices, and that the stream ID is
        updated accordingly.
        """
        interested_service = self._mkservice(is_interested_in_event=True)
        services = [interested_service]
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_type_stream_id_for_appservice.return_value = make_awaitable(
            579
        )

        event = Mock(event_id="event_1")
        self.event_source.sources.receipt.get_new_events_as.return_value = (
            make_awaitable(([event], None))
        )

        self.handler.notify_interested_services_ephemeral(
            "receipt_key", 580, ["@fakerecipient:example.com"]
        )
        self.mock_scheduler.enqueue_for_appservice.assert_called_once_with(
            interested_service, ephemeral=[event]
        )
        self.mock_store.set_appservice_stream_type_pos.assert_called_once_with(
            interested_service,
            "read_receipt",
            580,
        )

    def test_notify_interested_services_ephemeral_out_of_order(self):
        """
        Test sending out of order ephemeral events to the appservice handler
        are ignored.
        """
        interested_service = self._mkservice(is_interested_in_event=True)
        services = [interested_service]

        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_type_stream_id_for_appservice.return_value = make_awaitable(
            580
        )

        event = Mock(event_id="event_1")
        self.event_source.sources.receipt.get_new_events_as.return_value = (
            make_awaitable(([event], None))
        )

        self.handler.notify_interested_services_ephemeral(
            "receipt_key", 580, ["@fakerecipient:example.com"]
        )
        # This method will be called, but with an empty list of events
        self.mock_scheduler.enqueue_for_appservice.assert_called_once_with(
            interested_service, ephemeral=[]
        )

    def _mkservice(
        self, is_interested_in_event: bool, protocols: Optional[Iterable] = None
    ) -> Mock:
        """
        Create a new mock representing an ApplicationService.

        Args:
            is_interested_in_event: Whether this application service will be considered
                interested in all events.
            protocols: The third-party protocols that this application service claims to
                support.

        Returns:
            A mock representing the ApplicationService.
        """
        service = Mock()
        service.is_interested_in_event.return_value = make_awaitable(
            is_interested_in_event
        )
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        service.protocols = protocols
        return service

    def _mkservice_alias(self, is_room_alias_in_namespace: bool) -> Mock:
        """
        Create a new mock representing an ApplicationService that is or is not interested
        any given room aliase.

        Args:
            is_room_alias_in_namespace: If true, the application service will be interested
                in all room aliases that are queried against it. If false, the application
                service will not be interested in any room aliases.

        Returns:
            A mock representing the ApplicationService.
        """
        service = Mock()
        service.is_room_alias_in_namespace.return_value = is_room_alias_in_namespace
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        return service


class ApplicationServicesHandlerSendEventsTestCase(unittest.HomeserverTestCase):
    """
    Tests that the ApplicationServicesHandler sends events to application
    services correctly.
    """

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
        sendtodevice.register_servlets,
        receipts.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer):
        self.hs = hs
        # Mock the ApplicationServiceScheduler's _TransactionController's send method so that
        # we can track any outgoing ephemeral events
        self.send_mock = simple_async_mock()
        hs.get_application_service_handler().scheduler.txn_ctrl.send = self.send_mock  # type: ignore[assignment]

        # Mock out application services, and allow defining our own in tests
        self._services: List[ApplicationService] = []
        self.hs.get_datastores().main.get_app_services = Mock(  # type: ignore[assignment]
            return_value=self._services
        )

        # A user on the homeserver.
        self.local_user_device_id = "local_device"
        self.local_user = self.register_user("local_user", "password")
        self.local_user_token = self.login(
            "local_user", "password", self.local_user_device_id
        )

        # A user on the homeserver which lies within an appservice's exclusive user namespace.
        self.exclusive_as_user_device_id = "exclusive_as_device"
        self.exclusive_as_user = self.register_user("exclusive_as_user", "password")
        self.exclusive_as_user_token = self.login(
            "exclusive_as_user", "password", self.exclusive_as_user_device_id
        )

    def _notify_interested_services(self):
        # This is normally set in `notify_interested_services` but we need to call the
        # internal async version so the reactor gets pushed to completion.
        self.hs.get_application_service_handler().current_max += 1
        self.get_success(
            self.hs.get_application_service_handler()._notify_interested_services(
                RoomStreamToken(
                    None, self.hs.get_application_service_handler().current_max
                )
            )
        )

    @parameterized.expand(
        [
            ("@local_as_user:test", True),
            # Defining remote users in an application service user namespace regex is a
            # footgun since the appservice might assume that it'll receive all events
            # sent by that remote user, but it will only receive events in rooms that
            # are shared with a local user. So we just remove this footgun possibility
            # entirely and we won't notify the application service based on remote
            # users.
            ("@remote_as_user:remote", False),
        ]
    )
    def test_match_interesting_room_members(
        self, interesting_user: str, should_notify: bool
    ):
        """
        Test to make sure that a interesting user (local or remote) in the room is
        notified as expected when someone else in the room sends a message.
        """
        # Register an application service that's interested in the `interesting_user`
        interested_appservice = self._register_application_service(
            namespaces={
                ApplicationService.NS_USERS: [
                    {
                        "regex": interesting_user,
                        "exclusive": False,
                    },
                ],
            },
        )

        # Create a room
        alice = self.register_user("alice", "pass")
        alice_access_token = self.login("alice", "pass")
        room_id = self.helper.create_room_as(room_creator=alice, tok=alice_access_token)

        # Join the interesting user to the room
        self.get_success(
            event_injection.inject_member_event(
                self.hs, room_id, interesting_user, "join"
            )
        )
        # Kick the appservice into checking this membership event to get the event out
        # of the way
        self._notify_interested_services()
        # We don't care about the interesting user join event (this test is making sure
        # the next thing works)
        self.send_mock.reset_mock()

        # Send a message from an uninteresting user
        self.helper.send_event(
            room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "message from uninteresting user",
            },
            tok=alice_access_token,
        )
        # Kick the appservice into checking this new event
        self._notify_interested_services()

        if should_notify:
            self.send_mock.assert_called_once()
            (
                service,
                events,
                _ephemeral,
                _to_device_messages,
                _otks,
                _fbks,
                _device_list_summary,
            ) = self.send_mock.call_args[0]

            # Even though the message came from an uninteresting user, it should still
            # notify us because the interesting user is joined to the room where the
            # message was sent.
            self.assertEqual(service, interested_appservice)
            self.assertEqual(events[0]["type"], "m.room.message")
            self.assertEqual(events[0]["sender"], alice)
        else:
            self.send_mock.assert_not_called()

    def test_application_services_receive_events_sent_by_interesting_local_user(self):
        """
        Test to make sure that a messages sent from a local user can be interesting and
        picked up by the appservice.
        """
        # Register an application service that's interested in all local users
        interested_appservice = self._register_application_service(
            namespaces={
                ApplicationService.NS_USERS: [
                    {
                        "regex": ".*",
                        "exclusive": False,
                    },
                ],
            },
        )

        # Create a room
        alice = self.register_user("alice", "pass")
        alice_access_token = self.login("alice", "pass")
        room_id = self.helper.create_room_as(room_creator=alice, tok=alice_access_token)

        # We don't care about interesting events before this (this test is making sure
        # the next thing works)
        self.send_mock.reset_mock()

        # Send a message from the interesting local user
        self.helper.send_event(
            room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "message from interesting local user",
            },
            tok=alice_access_token,
        )
        # Kick the appservice into checking this new event
        self._notify_interested_services()

        self.send_mock.assert_called_once()
        (
            service,
            events,
            _ephemeral,
            _to_device_messages,
            _otks,
            _fbks,
            _device_list_summary,
        ) = self.send_mock.call_args[0]

        # Events sent from an interesting local user should also be picked up as
        # interesting to the appservice.
        self.assertEqual(service, interested_appservice)
        self.assertEqual(events[0]["type"], "m.room.message")
        self.assertEqual(events[0]["sender"], alice)

    def test_sending_read_receipt_batches_to_application_services(self):
        """Tests that a large batch of read receipts are sent correctly to
        interested application services.
        """
        # Register an application service that's interested in a certain user
        # and room prefix
        interested_appservice = self._register_application_service(
            namespaces={
                ApplicationService.NS_USERS: [
                    {
                        "regex": "@exclusive_as_user:.+",
                        "exclusive": True,
                    }
                ],
                ApplicationService.NS_ROOMS: [
                    {
                        "regex": "!fakeroom_.*",
                        "exclusive": True,
                    }
                ],
            },
        )

        # Now, pretend that we receive a large burst of read receipts (300 total) that
        # all come in at once.
        for i in range(300):
            self.get_success(
                # Insert a fake read receipt into the database
                self.hs.get_datastores().main.insert_receipt(
                    # We have to use unique room ID + user ID combinations here, as the db query
                    # is an upsert.
                    room_id=f"!fakeroom_{i}:test",
                    receipt_type="m.read",
                    user_id=self.local_user,
                    event_ids=[f"$eventid_{i}"],
                    thread_id=None,
                    data={},
                )
            )

        # Now notify the appservice handler that 300 read receipts have all arrived
        # at once. What will it do!
        # note: stream tokens start at 2
        for stream_token in range(2, 303):
            self.get_success(
                self.hs.get_application_service_handler()._notify_interested_services_ephemeral(
                    services=[interested_appservice],
                    stream_key="receipt_key",
                    new_token=stream_token,
                    users=[self.exclusive_as_user],
                )
            )

        # Using our txn send mock, we can see what the AS received. After iterating over every
        # transaction, we'd like to see all 300 read receipts accounted for.
        # No more, no less.
        all_ephemeral_events = []
        for call in self.send_mock.call_args_list:
            ephemeral_events = call[0][2]
            all_ephemeral_events += ephemeral_events

        # Ensure that no duplicate events were sent
        self.assertEqual(len(all_ephemeral_events), 300)

        # Check that the ephemeral event is a read receipt with the expected structure
        latest_read_receipt = all_ephemeral_events[-1]
        self.assertEqual(latest_read_receipt["type"], EduTypes.RECEIPT)

        event_id = list(latest_read_receipt["content"].keys())[0]
        self.assertEqual(
            latest_read_receipt["content"][event_id]["m.read"], {self.local_user: {}}
        )

    @unittest.override_config(
        {"experimental_features": {"msc2409_to_device_messages_enabled": True}}
    )
    def test_application_services_receive_local_to_device(self):
        """
        Test that when a user sends a to-device message to another user
        that is an application service's user namespace, the
        application service will receive it.
        """
        interested_appservice = self._register_application_service(
            namespaces={
                ApplicationService.NS_USERS: [
                    {
                        "regex": "@exclusive_as_user:.+",
                        "exclusive": True,
                    }
                ],
            },
        )

        # Have local_user send a to-device message to exclusive_as_user
        message_content = {"some_key": "some really interesting value"}
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.room_key_request/3",
            content={
                "messages": {
                    self.exclusive_as_user: {
                        self.exclusive_as_user_device_id: message_content
                    }
                }
            },
            access_token=self.local_user_token,
        )
        self.assertEqual(chan.code, 200, chan.result)

        # Have exclusive_as_user send a to-device message to local_user
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.room_key_request/4",
            content={
                "messages": {
                    self.local_user: {self.local_user_device_id: message_content}
                }
            },
            access_token=self.exclusive_as_user_token,
        )
        self.assertEqual(chan.code, 200, chan.result)

        # Check if our application service - that is interested in exclusive_as_user - received
        # the to-device message as part of an AS transaction.
        # Only the local_user -> exclusive_as_user to-device message should have been forwarded to the AS.
        #
        # The uninterested application service should not have been notified at all.
        self.send_mock.assert_called_once()
        (
            service,
            _events,
            _ephemeral,
            to_device_messages,
            _otks,
            _fbks,
            _device_list_summary,
        ) = self.send_mock.call_args[0]

        # Assert that this was the same to-device message that local_user sent
        self.assertEqual(service, interested_appservice)
        self.assertEqual(to_device_messages[0]["type"], "m.room_key_request")
        self.assertEqual(to_device_messages[0]["sender"], self.local_user)

        # Additional fields 'to_user_id' and 'to_device_id' specifically for
        # to-device messages via the AS API
        self.assertEqual(to_device_messages[0]["to_user_id"], self.exclusive_as_user)
        self.assertEqual(
            to_device_messages[0]["to_device_id"], self.exclusive_as_user_device_id
        )
        self.assertEqual(to_device_messages[0]["content"], message_content)

    @unittest.override_config(
        {"experimental_features": {"msc2409_to_device_messages_enabled": True}}
    )
    def test_application_services_receive_bursts_of_to_device(self):
        """
        Test that when a user sends >100 to-device messages at once, any
        interested AS's will receive them in separate transactions.

        Also tests that uninterested application services do not receive messages.
        """
        # Register two application services with exclusive interest in a user
        interested_appservices = []
        for _ in range(2):
            appservice = self._register_application_service(
                namespaces={
                    ApplicationService.NS_USERS: [
                        {
                            "regex": "@exclusive_as_user:.+",
                            "exclusive": True,
                        }
                    ],
                },
            )
            interested_appservices.append(appservice)

        # ...and an application service which does not have any user interest.
        self._register_application_service()

        to_device_message_content = {
            "some key": "some interesting value",
        }

        # We need to send a large burst of to-device messages. We also would like to
        # include them all in the same application service transaction so that we can
        # test large transactions.
        #
        # To do this, we can send a single to-device message to many user devices at
        # once.
        #
        # We insert number_of_messages - 1 messages into the database directly. We'll then
        # send a final to-device message to the real device, which will also kick off
        # an AS transaction (as just inserting messages into the DB won't).
        number_of_messages = 150
        fake_device_ids = [f"device_{num}" for num in range(number_of_messages - 1)]
        messages = {
            self.exclusive_as_user: {
                device_id: to_device_message_content for device_id in fake_device_ids
            }
        }

        # Create a fake device per message. We can't send to-device messages to
        # a device that doesn't exist.
        self.get_success(
            self.hs.get_datastores().main.db_pool.simple_insert_many(
                desc="test_application_services_receive_burst_of_to_device",
                table="devices",
                keys=("user_id", "device_id"),
                values=[
                    (
                        self.exclusive_as_user,
                        device_id,
                    )
                    for device_id in fake_device_ids
                ],
            )
        )

        # Seed the device_inbox table with our fake messages
        self.get_success(
            self.hs.get_datastores().main.add_messages_to_device_inbox(messages, {})
        )

        # Now have local_user send a final to-device message to exclusive_as_user. All unsent
        # to-device messages should be sent to any application services
        # interested in exclusive_as_user.
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.room_key_request/4",
            content={
                "messages": {
                    self.exclusive_as_user: {
                        self.exclusive_as_user_device_id: to_device_message_content
                    }
                }
            },
            access_token=self.local_user_token,
        )
        self.assertEqual(chan.code, 200, chan.result)

        self.send_mock.assert_called()

        # Count the total number of to-device messages that were sent out per-service.
        # Ensure that we only sent to-device messages to interested services, and that
        # each interested service received the full count of to-device messages.
        service_id_to_message_count: Dict[str, int] = {}

        for call in self.send_mock.call_args_list:
            (
                service,
                _events,
                _ephemeral,
                to_device_messages,
                _otks,
                _fbks,
                _device_list_summary,
            ) = call[0]

            # Check that this was made to an interested service
            self.assertIn(service, interested_appservices)

            # Add to the count of messages for this application service
            service_id_to_message_count.setdefault(service.id, 0)
            service_id_to_message_count[service.id] += len(to_device_messages)

        # Assert that each interested service received the full count of messages
        for count in service_id_to_message_count.values():
            self.assertEqual(count, number_of_messages)

    def _register_application_service(
        self,
        namespaces: Optional[Dict[str, Iterable[Dict]]] = None,
    ) -> ApplicationService:
        """
        Register a new application service, with the given namespaces of interest.

        Args:
            namespaces: A dictionary containing any user, room or alias namespaces that
                the application service is interested in.

        Returns:
            The registered application service.
        """
        # Create an application service
        appservice = ApplicationService(
            token=random_string(10),
            id=random_string(10),
            sender="@as:example.com",
            rate_limited=False,
            namespaces=namespaces,
            supports_ephemeral=True,
        )

        # Register the application service
        self._services.append(appservice)

        return appservice


class ApplicationServicesHandlerDeviceListsTestCase(unittest.HomeserverTestCase):
    """
    Tests that the ApplicationServicesHandler sends device list updates to application
    services correctly.
    """

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # Allow us to modify cached feature flags mid-test
        self.as_handler = hs.get_application_service_handler()

        # Mock ApplicationServiceApi's put_json, so we can verify the raw JSON that
        # will be sent over the wire
        self.put_json = simple_async_mock()
        hs.get_application_service_api().put_json = self.put_json  # type: ignore[assignment]

        # Mock out application services, and allow defining our own in tests
        self._services: List[ApplicationService] = []
        self.hs.get_datastores().main.get_app_services = Mock(
            return_value=self._services
        )

    # Test across a variety of configuration values
    @parameterized.expand(
        [
            (True, True, True),
            (True, False, False),
            (False, True, False),
            (False, False, False),
        ]
    )
    def test_application_service_receives_device_list_updates(
        self,
        experimental_feature_enabled: bool,
        as_supports_txn_extensions: bool,
        as_should_receive_device_list_updates: bool,
    ):
        """
        Tests that an application service receives notice of changed device
        lists for a user, when a user changes their device lists.

        Arguments above are populated by parameterized.

        Args:
            as_should_receive_device_list_updates: Whether we expect the AS to receive the
                device list changes.
            experimental_feature_enabled: Whether the "msc3202_transaction_extensions" experimental
                feature is enabled. This feature must be enabled for device lists to ASs to work.
            as_supports_txn_extensions: Whether the application service has explicitly registered
                to receive information defined by MSC3202 - which includes device list changes.
        """
        # Change whether the experimental feature is enabled or disabled before making
        # device list changes
        self.as_handler._msc3202_transaction_extensions_enabled = (
            experimental_feature_enabled
        )

        # Create an appservice that is interested in "local_user"
        appservice = ApplicationService(
            token=random_string(10),
            id=random_string(10),
            sender="@as:example.com",
            rate_limited=False,
            namespaces={
                ApplicationService.NS_USERS: [
                    {
                        "regex": "@local_user:.+",
                        "exclusive": False,
                    }
                ],
            },
            supports_ephemeral=True,
            msc3202_transaction_extensions=as_supports_txn_extensions,
            # Must be set for Synapse to try pushing data to the AS
            hs_token="abcde",
            url="some_url",
        )

        # Register the application service
        self._services.append(appservice)

        # Register a user on the homeserver
        self.local_user = self.register_user("local_user", "password")
        self.local_user_token = self.login("local_user", "password")

        if as_should_receive_device_list_updates:
            # Ensure that the resulting JSON uses the unstable prefix and contains the
            # expected users
            self.put_json.assert_called_once()
            json_body = self.put_json.call_args[1]["json_body"]

            # Our application service should have received a device list update with
            # "local_user" in the "changed" list
            device_list_dict = json_body.get("org.matrix.msc3202.device_lists", {})
            self.assertEqual([], device_list_dict["left"])
            self.assertEqual([self.local_user], device_list_dict["changed"])

        else:
            # No device list changes should have been sent out
            self.put_json.assert_not_called()


class ApplicationServicesHandlerOtkCountsTestCase(unittest.HomeserverTestCase):
    # Argument indices for pulling out arguments from a `send_mock`.
    ARG_OTK_COUNTS = 4
    ARG_FALLBACK_KEYS = 5

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        register.register_servlets,
        room.register_servlets,
        sendtodevice.register_servlets,
        receipts.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # Mock the ApplicationServiceScheduler's _TransactionController's send method so that
        # we can track what's going out
        self.send_mock = simple_async_mock()
        hs.get_application_service_handler().scheduler.txn_ctrl.send = self.send_mock  # type: ignore[assignment]  # We assign to a method.

        # Define an application service for the tests
        self._service_token = "VERYSECRET"
        self._service = ApplicationService(
            self._service_token,
            "as1",
            "@as.sender:test",
            namespaces={
                "users": [
                    {"regex": "@_as_.*:test", "exclusive": True},
                    {"regex": "@as.sender:test", "exclusive": True},
                ]
            },
            msc3202_transaction_extensions=True,
        )
        self.hs.get_datastores().main.services_cache = [self._service]

        # Register some appservice users
        self._sender_user, self._sender_device = self.register_appservice_user(
            "as.sender", self._service_token
        )
        self._namespaced_user, self._namespaced_device = self.register_appservice_user(
            "_as_user1", self._service_token
        )

        # Register a real user as well.
        self._real_user = self.register_user("real.user", "meow")
        self._real_user_token = self.login("real.user", "meow")

    async def _add_otks_for_device(
        self, user_id: str, device_id: str, otk_count: int
    ) -> None:
        """
        Add some dummy keys. It doesn't matter if they're not a real algorithm;
        that should be opaque to the server anyway.
        """
        await self.hs.get_datastores().main.add_e2e_one_time_keys(
            user_id,
            device_id,
            self.clock.time_msec(),
            [("algo", f"k{i}", "{}") for i in range(otk_count)],
        )

    async def _add_fallback_key_for_device(
        self, user_id: str, device_id: str, used: bool
    ) -> None:
        """
        Adds a fake fallback key to a device, optionally marking it as used
        right away.
        """
        store = self.hs.get_datastores().main
        await store.set_e2e_fallback_keys(user_id, device_id, {"algo:fk": "fall back!"})
        if used is True:
            # Mark the key as used
            await store.db_pool.simple_update_one(
                table="e2e_fallback_keys_json",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                    "algorithm": "algo",
                    "key_id": "fk",
                },
                updatevalues={"used": True},
                desc="_get_fallback_key_set_used",
            )

    def _set_up_devices_and_a_room(self) -> str:
        """
        Helper to set up devices for all the users
        and a room for the users to talk in.
        """

        async def preparation():
            await self._add_otks_for_device(self._sender_user, self._sender_device, 42)
            await self._add_fallback_key_for_device(
                self._sender_user, self._sender_device, used=True
            )
            await self._add_otks_for_device(
                self._namespaced_user, self._namespaced_device, 36
            )
            await self._add_fallback_key_for_device(
                self._namespaced_user, self._namespaced_device, used=False
            )

            # Register a device for the real user, too, so that we can later ensure
            # that we don't leak information to the AS about the non-AS user.
            await self.hs.get_datastores().main.store_device(
                self._real_user, "REALDEV", "UltraMatrix 3000"
            )
            await self._add_otks_for_device(self._real_user, "REALDEV", 50)

        self.get_success(preparation())

        room_id = self.helper.create_room_as(
            self._real_user, is_public=True, tok=self._real_user_token
        )
        self.helper.join(
            room_id,
            self._namespaced_user,
            tok=self._service_token,
            appservice_user_id=self._namespaced_user,
        )

        # Check it was called for sanity. (This was to send the join event to the AS.)
        self.send_mock.assert_called()
        self.send_mock.reset_mock()

        return room_id

    @override_config(
        {"experimental_features": {"msc3202_transaction_extensions": True}}
    )
    def test_application_services_receive_otk_counts_and_fallback_key_usages_with_pdus(
        self,
    ) -> None:
        """
        Tests that:
        - the AS receives one-time key counts and unused fallback keys for:
            - the specified sender; and
            - any user who is in receipt of the PDUs
        """

        room_id = self._set_up_devices_and_a_room()

        # Send a message into the AS's room
        self.helper.send(room_id, "woof woof", tok=self._real_user_token)

        # Capture what was sent as an AS transaction.
        self.send_mock.assert_called()
        last_args, _last_kwargs = self.send_mock.call_args
        otks: Optional[TransactionOneTimeKeyCounts] = last_args[self.ARG_OTK_COUNTS]
        unused_fallbacks: Optional[TransactionUnusedFallbackKeys] = last_args[
            self.ARG_FALLBACK_KEYS
        ]

        self.assertEqual(
            otks,
            {
                "@as.sender:test": {self._sender_device: {"algo": 42}},
                "@_as_user1:test": {self._namespaced_device: {"algo": 36}},
            },
        )
        self.assertEqual(
            unused_fallbacks,
            {
                "@as.sender:test": {self._sender_device: []},
                "@_as_user1:test": {self._namespaced_device: ["algo"]},
            },
        )
