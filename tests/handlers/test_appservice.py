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

from twisted.internet import defer
from .. import unittest
from tests.utils import MockClock

from synapse.handlers.appservice import ApplicationServicesHandler

from mock import Mock


class AppServiceHandlerTestCase(unittest.TestCase):
    """ Tests the ApplicationServicesHandler. """

    def setUp(self):
        self.mock_store = Mock()
        self.mock_as_api = Mock()
        self.mock_scheduler = Mock()
        hs = Mock()
        hs.get_datastore = Mock(return_value=self.mock_store)
        hs.get_application_service_api = Mock(return_value=self.mock_as_api)
        hs.get_application_service_scheduler = Mock(return_value=self.mock_scheduler)
        hs.get_clock.return_value = MockClock()
        self.handler = ApplicationServicesHandler(hs)

    @defer.inlineCallbacks
    def test_notify_interested_services(self):
        interested_service = self._mkservice(is_interested=True)
        services = [
            self._mkservice(is_interested=False),
            interested_service,
            self._mkservice(is_interested=False)
        ]

        self.mock_store.get_app_services = Mock(return_value=services)
        self.mock_store.get_user_by_id = Mock(return_value=[])

        event = Mock(
            sender="@someone:anywhere",
            type="m.room.message",
            room_id="!foo:bar"
        )
        self.mock_store.get_new_events_for_appservice.return_value = (0, [event])
        self.mock_as_api.push = Mock()
        yield self.handler.notify_interested_services(0)
        self.mock_scheduler.submit_event_for_as.assert_called_once_with(
            interested_service, event
        )

    @defer.inlineCallbacks
    def test_query_user_exists_unknown_user(self):
        user_id = "@someone:anywhere"
        services = [self._mkservice(is_interested=True)]
        services[0].is_interested_in_user = Mock(return_value=True)
        self.mock_store.get_app_services = Mock(return_value=services)
        self.mock_store.get_user_by_id = Mock(return_value=None)

        event = Mock(
            sender=user_id,
            type="m.room.message",
            room_id="!foo:bar"
        )
        self.mock_as_api.push = Mock()
        self.mock_as_api.query_user = Mock()
        self.mock_store.get_new_events_for_appservice.return_value = (0, [event])
        yield self.handler.notify_interested_services(0)
        self.mock_as_api.query_user.assert_called_once_with(
            services[0], user_id
        )

    @defer.inlineCallbacks
    def test_query_user_exists_known_user(self):
        user_id = "@someone:anywhere"
        services = [self._mkservice(is_interested=True)]
        services[0].is_interested_in_user = Mock(return_value=True)
        self.mock_store.get_app_services = Mock(return_value=services)
        self.mock_store.get_user_by_id = Mock(return_value={
            "name": user_id
        })

        event = Mock(
            sender=user_id,
            type="m.room.message",
            room_id="!foo:bar"
        )
        self.mock_as_api.push = Mock()
        self.mock_as_api.query_user = Mock()
        self.mock_store.get_new_events_for_appservice.return_value = (0, [event])
        yield self.handler.notify_interested_services(0)
        self.assertFalse(
            self.mock_as_api.query_user.called,
            "query_user called when it shouldn't have been."
        )

    @defer.inlineCallbacks
    def test_query_room_alias_exists(self):
        room_alias_str = "#foo:bar"
        room_alias = Mock()
        room_alias.to_string = Mock(return_value=room_alias_str)

        room_id = "!alpha:bet"
        servers = ["aperture"]
        interested_service = self._mkservice_alias(is_interested_in_alias=True)
        services = [
            self._mkservice_alias(is_interested_in_alias=False),
            interested_service,
            self._mkservice_alias(is_interested_in_alias=False)
        ]

        self.mock_store.get_app_services = Mock(return_value=services)
        self.mock_store.get_association_from_room_alias = Mock(
            return_value=Mock(room_id=room_id, servers=servers)
        )

        result = yield self.handler.query_room_alias_exists(room_alias)

        self.mock_as_api.query_alias.assert_called_once_with(
            interested_service,
            room_alias_str
        )
        self.assertEquals(result.room_id, room_id)
        self.assertEquals(result.servers, servers)

    def _mkservice(self, is_interested):
        service = Mock()
        service.is_interested = Mock(return_value=is_interested)
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        return service

    def _mkservice_alias(self, is_interested_in_alias):
        service = Mock()
        service.is_interested_in_alias = Mock(return_value=is_interested_in_alias)
        service.token = "mock_service_token"
        service.url = "mock_service_url"
        return service
