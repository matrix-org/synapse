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

from typing import Dict, Iterable, List, Optional, Tuple
from unittest.mock import Mock

from twisted.internet import defer

import synapse.rest.admin
import synapse.storage
from synapse.appservice import ApplicationService
from synapse.handlers.appservice import ApplicationServicesHandler
from synapse.rest.client import login, receipts, room, sendtodevice
from synapse.types import RoomStreamToken
from synapse.util.stringutils import random_string

from tests import unittest
from tests.test_utils import make_awaitable
from tests.utils import MockClock


class AppServiceHandlerTestCase(unittest.TestCase):
    """Tests the ApplicationServicesHandler."""

    def setUp(self):
        self.mock_store = Mock()
        self.mock_as_api = Mock()
        self.mock_scheduler = Mock()
        hs = Mock()
        hs.get_datastore.return_value = self.mock_store
        self.mock_store.get_received_ts.return_value = make_awaitable(0)
        self.mock_store.set_appservice_last_pos.return_value = make_awaitable(None)
        hs.get_application_service_api.return_value = self.mock_as_api
        hs.get_application_service_scheduler.return_value = self.mock_scheduler
        hs.get_clock.return_value = MockClock()
        self.handler = ApplicationServicesHandler(hs)
        self.event_source = hs.get_event_sources()

        # Mock the ApplicationServiceScheduler queuer so that we can track any
        # outgoing ephemeral events
        self.mock_service_queuer = Mock()
        self.mock_service_queuer.enqueue_ephemeral = Mock()
        hs.get_application_service_handler().scheduler.queuer = self.mock_service_queuer

    def test_notify_interested_services(self):
        interested_service = self._mkservice(is_interested=True)
        services = [
            self._mkservice(is_interested=False),
            interested_service,
            self._mkservice(is_interested=False),
        ]

        self.mock_as_api.query_user.return_value = make_awaitable(True)
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_user_by_id.return_value = make_awaitable([])

        event = Mock(
            sender="@someone:anywhere", type="m.room.message", room_id="!foo:bar"
        )
        self.mock_store.get_new_events_for_appservice.side_effect = [
            make_awaitable((0, [])),
            make_awaitable((1, [event])),
        ]
        self.handler.notify_interested_services(RoomStreamToken(None, 1))

        self.mock_scheduler.submit_event_for_as.assert_called_once_with(
            interested_service, event
        )

    def test_query_user_exists_unknown_user(self):
        user_id = "@someone:anywhere"
        services = [self._mkservice(is_interested=True)]
        services[0].is_interested_in_user.return_value = True
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_user_by_id.return_value = make_awaitable(None)

        event = Mock(sender=user_id, type="m.room.message", room_id="!foo:bar")
        self.mock_as_api.query_user.return_value = make_awaitable(True)
        self.mock_store.get_new_events_for_appservice.side_effect = [
            make_awaitable((0, [event])),
        ]

        self.handler.notify_interested_services(RoomStreamToken(None, 0))

        self.mock_as_api.query_user.assert_called_once_with(services[0], user_id)

    def test_query_user_exists_known_user(self):
        user_id = "@someone:anywhere"
        services = [self._mkservice(is_interested=True)]
        services[0].is_interested_in_user.return_value = True
        self.mock_store.get_app_services.return_value = services
        self.mock_store.get_user_by_id.return_value = make_awaitable({"name": user_id})

        event = Mock(sender=user_id, type="m.room.message", room_id="!foo:bar")
        self.mock_as_api.query_user.return_value = make_awaitable(True)
        self.mock_store.get_new_events_for_appservice.side_effect = [
            make_awaitable((0, [event])),
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
        interested_service = self._mkservice_alias(is_interested_in_alias=True)
        services = [
            self._mkservice_alias(is_interested_in_alias=False),
            interested_service,
            self._mkservice_alias(is_interested_in_alias=False),
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
        self.assertEquals(result.room_id, room_id)
        self.assertEquals(result.servers, servers)

    def test_get_3pe_protocols_no_appservices(self):
        self.mock_store.get_app_services.return_value = []
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols("my-protocol"))
        )
        self.mock_as_api.get_3pe_protocol.assert_not_called()
        self.assertEquals(response, {})

    def test_get_3pe_protocols_no_protocols(self):
        service = self._mkservice(False, [])
        self.mock_store.get_app_services.return_value = [service]
        response = self.successResultOf(
            defer.ensureDeferred(self.handler.get_3pe_protocols())
        )
        self.mock_as_api.get_3pe_protocol.assert_not_called()
        self.assertEquals(response, {})

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
        self.assertEquals(response, {})

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
        self.assertEquals(
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
        self.assertEquals(
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
        self.assertEquals(
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
        self.assertEquals(
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
        interested_service = self._mkservice(is_interested=True)
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
        self.mock_service_queuer.enqueue_ephemeral.assert_called_once_with(
            interested_service, [event]
        )
        self.mock_store.set_type_stream_id_for_appservice.assert_called_once_with(
            interested_service,
            "read_receipt",
            580,
        )

    def test_notify_interested_services_ephemeral_out_of_order(self):
        """
        Test sending out of order ephemeral events to the appservice handler
        are ignored.
        """
        interested_service = self._mkservice(is_interested=True)
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
        self.mock_service_queuer.enqueue_ephemeral.assert_not_called()

    def _mkservice(self, is_interested, protocols=None):
        service = Mock()
        service.is_interested.return_value = make_awaitable(is_interested)
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        service.protocols = protocols
        return service

    def _mkservice_alias(self, is_interested_in_alias):
        service = Mock()
        service.is_interested_in_alias.return_value = is_interested_in_alias
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        return service


class ApplicationServiceEphemeralEventsTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
        sendtodevice.register_servlets,
        receipts.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        # Mock the ApplicationServiceScheduler queuer so that we can track any
        # outgoing ephemeral events
        self.mock_service_queuer = Mock()
        self.mock_service_queuer.enqueue_ephemeral = Mock()
        hs.get_application_service_handler().scheduler.queuer = self.mock_service_queuer

        self.device1 = "device1"
        self.user1 = self.register_user("user1", "password")
        self.token1 = self.login("user1", "password", self.device1)

        self.device2 = "device2"
        self.user2 = self.register_user("user2", "password")
        self.token2 = self.login("user2", "password", self.device2)

    @unittest.override_config(
        {"experimental_features": {"msc2409_to_device_messages_enabled": True}}
    )
    def test_application_services_receive_local_to_device(self):
        """
        Test that when a user sends a to-device message to another user, and
        that is in an application service's user namespace, that application
        service will receive it.
        """
        (
            interested_services,
            _,
        ) = self._register_interested_and_uninterested_application_services()
        interested_service = interested_services[0]

        # Have user1 send a to-device message to user2
        message_content = {"some_key": "some really interesting value"}
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.room_key_request/3",
            content={"messages": {self.user2: {self.device2: message_content}}},
            access_token=self.token1,
        )
        self.assertEqual(chan.code, 200, chan.result)

        # Have user2 send a to-device message to user1
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.room_key_request/4",
            content={"messages": {self.user1: {self.device1: message_content}}},
            access_token=self.token2,
        )
        self.assertEqual(chan.code, 200, chan.result)

        # Check if our application service - that is interested in user2 - received
        # the to-device message as part of an AS transaction.
        # Only the user1 -> user2 to-device message should have been forwarded to the AS.
        #
        # The uninterested application service should not have been notified at all.
        self.mock_service_queuer.enqueue_ephemeral.assert_called_once()
        service, events = self.mock_service_queuer.enqueue_ephemeral.call_args[
            0
        ]

        # Assert that this was the same to-device message that user1 sent
        self.assertEqual(service, interested_service)
        self.assertEqual(events[0]["type"], "m.room_key_request")
        self.assertEqual(events[0]["sender"], self.user1)

        # Additional fields 'to_user_id' and 'to_device_id' specifically for
        # to-device messages via the AS API
        self.assertEqual(events[0]["to_user_id"], self.user2)
        self.assertEqual(events[0]["to_device_id"], self.device2)
        self.assertEqual(events[0]["content"], message_content)

    @unittest.override_config(
        {"experimental_features": {"msc2409_to_device_messages_enabled": True}}
    )
    def test_application_services_receive_bursts_of_to_device(self):
        """
        Test that when a user sends >100 to-device messages at once, any
        interested AS's will receive them in separate transactions.
        """
        (
            interested_services,
            _,
        ) = self._register_interested_and_uninterested_application_services(
            interested_count=2,
            uninterested_count=2,
        )

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
            self.user2: {
                device_id: to_device_message_content for device_id in fake_device_ids
            }
        }

        # Create a fake device per message. We can't send to-device messages to
        # a device that doesn't exist.
        self.get_success(
            self.hs.get_datastore().db_pool.simple_insert_many(
                desc="test_application_services_receive_burst_of_to_device",
                table="devices",
                values=[
                    {
                        "user_id": self.user2,
                        "device_id": device_id,
                    }
                    for device_id in fake_device_ids
                ],
            )
        )

        # Seed the device_inbox table with our fake messages
        self.get_success(
            self.hs.get_datastore().add_messages_to_device_inbox(messages, {})
        )

        # Now have user1 send a final to-device message to user2. All unsent
        # to-device messages should be sent to any application services
        # interested in user2.
        chan = self.make_request(
            "PUT",
            "/_matrix/client/r0/sendToDevice/m.room_key_request/4",
            content={
                "messages": {self.user2: {self.device2: to_device_message_content}}
            },
            access_token=self.token1,
        )
        self.assertEqual(chan.code, 200, chan.result)

        self.mock_service_queuer.enqueue_ephemeral.assert_called()

        # Count the total number of to-device messages that were sent out per-service.
        # Ensure that we only sent to-device messages to interested services, and that
        # each interested service received the full count of to-device messages.
        service_id_to_message_count: Dict[str, int] = {}

        for call in self.mock_service_queuer.enqueue_ephemeral.call_args_list:
            service, events = call[0]

            # Check that this was made to an interested service
            self.assertIn(service, interested_services)

            # Add to the count of messages for this application service
            service_id_to_message_count.setdefault(service.id, 0)
            service_id_to_message_count[service.id] += len(events)

        # Assert that each interested service received the full count of messages
        for count in service_id_to_message_count.values():
            self.assertEqual(count, number_of_messages)

    def _register_interested_and_uninterested_application_services(
        self,
        interested_count: int = 1,
        uninterested_count: int = 1,
    ) -> Tuple[List[ApplicationService], List[ApplicationService]]:
        """
        Create application services with and without exclusive interest
        in user2.

        Args:
            interested_count: The number of application services to create
                and register with exclusive interest.
            uninterested_count: The number of application services to create
                and register without any interest.

        Returns:
            A two-tuple containing:
                * Interested application services
                * Uninterested application services
        """
        # Create an application service with exclusive interest in user2
        interested_services = []
        uninterested_services = []
        for _ in range(interested_count):
            interested_service = self._make_application_service(
                namespaces={
                    ApplicationService.NS_USERS: [
                        {
                            "regex": "@user2:.+",
                            "exclusive": True,
                        }
                    ],
                },
            )
            interested_services.append(interested_service)

        for _ in range(uninterested_count):
            uninterested_services.append(self._make_application_service())

        # Register this application service, along with another, uninterested one
        services = [
            *uninterested_services,
            *interested_services,
        ]
        self.hs.get_datastore().get_app_services = Mock(return_value=services)

        return interested_services, uninterested_services

    def _make_application_service(
        self,
        namespaces: Optional[Dict[str, Iterable[Dict]]] = None,
    ) -> ApplicationService:
        return ApplicationService(
            token=None,
            hostname="example.com",
            id=random_string(10),
            sender="@as:example.com",
            rate_limited=False,
            namespaces=namespaces,
            supports_ephemeral=True,
        )
