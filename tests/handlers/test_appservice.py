# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from mock import Mock

from twisted.internet import defer

from synapse.handlers.appservice import ApplicationServicesHandler
from synapse.types import RoomStreamToken

from tests.test_utils import make_awaitable
from tests.utils import MockClock

from .. import unittest


class AppServiceHandlerTestCase(unittest.TestCase):
    """ Tests the ApplicationServicesHandler. """

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
            make_awaitable((0, [event])),
            make_awaitable((0, [])),
        ]
        self.handler.notify_interested_services(RoomStreamToken(None, 0))

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
            make_awaitable((0, [])),
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
            make_awaitable((0, [])),
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

    def _mkservice(self, is_interested):
        service = Mock()
        service.is_interested.return_value = make_awaitable(is_interested)
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        return service

    def _mkservice_alias(self, is_interested_in_alias):
        service = Mock()
        service.is_interested_in_alias.return_value = is_interested_in_alias
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        return service
