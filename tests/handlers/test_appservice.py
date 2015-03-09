# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.handlers.appservice import ApplicationServicesHandler

from mock import Mock


class AppServiceHandlerTestCase(unittest.TestCase):
    """ Tests the ApplicationServicesHandler. """

    def setUp(self):
        self.mock_store = Mock()
        self.mock_as_api = Mock()
        hs = Mock()
        hs.get_datastore = Mock(return_value=self.mock_store)
        self.handler = ApplicationServicesHandler(
            hs, self.mock_as_api
        )

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
        self.mock_as_api.push = Mock()
        yield self.handler.notify_interested_services(event)
        self.mock_as_api.push.assert_called_once_with(interested_service, event)

    @defer.inlineCallbacks
    def test_query_room_alias_exists(self):
        room_alias_str = "#foo:bar"
        room_alias = Mock()
        room_alias.to_string = Mock(return_value=room_alias_str)

        room_id = "!alpha:bet"
        servers = ["aperture"]
        interested_service = self._mkservice(is_interested=True)
        services = [
            self._mkservice(is_interested=False),
            interested_service,
            self._mkservice(is_interested=False)
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
