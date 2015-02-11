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
from tests import unittest
from twisted.internet import defer

from synapse.appservice import ApplicationService
from synapse.server import HomeServer
from synapse.storage.appservice import ApplicationServiceStore

from mock import Mock
from tests.utils import SQLiteMemoryDbPool, MockClock


class ApplicationServiceStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()
        hs = HomeServer(
            "test", db_pool=db_pool, clock=MockClock(), config=Mock()
        )
        self.as_token = "token1"
        db_pool.runQuery(
            "INSERT INTO application_services(token) VALUES(?)",
            (self.as_token,)
        )
        db_pool.runQuery(
            "INSERT INTO application_services(token) VALUES(?)", ("token2",)
        )
        db_pool.runQuery(
            "INSERT INTO application_services(token) VALUES(?)", ("token3",)
        )
        # must be done after inserts
        self.store = ApplicationServiceStore(hs)

    @defer.inlineCallbacks
    def test_update_and_retrieval_of_service(self):
        url = "https://matrix.org/appservices/foobar"
        hs_token = "hstok"
        user_regex = ["@foobar_.*:matrix.org"]
        alias_regex = ["#foobar_.*:matrix.org"]
        room_regex = []
        service = ApplicationService(
            url=url, hs_token=hs_token, token=self.as_token, namespaces={
                ApplicationService.NS_USERS: user_regex,
                ApplicationService.NS_ALIASES: alias_regex,
                ApplicationService.NS_ROOMS: room_regex
        })
        yield self.store.update_app_service(service)

        stored_service = yield self.store.get_app_service_by_token(
            self.as_token
        )
        self.assertEquals(stored_service.token, self.as_token)
        self.assertEquals(stored_service.url, url)
        self.assertEquals(
            stored_service.namespaces[ApplicationService.NS_ALIASES],
            alias_regex
        )
        self.assertEquals(
            stored_service.namespaces[ApplicationService.NS_ROOMS],
            room_regex
        )
        self.assertEquals(
            stored_service.namespaces[ApplicationService.NS_USERS],
            user_regex
        )

    @defer.inlineCallbacks
    def test_retrieve_unknown_service_token(self):
        service = yield self.store.get_app_service_by_token("invalid_token")
        self.assertEquals(service, None)

    @defer.inlineCallbacks
    def test_retrieval_of_service(self):
        stored_service = yield self.store.get_app_service_by_token(
            self.as_token
        )
        self.assertEquals(stored_service.token, self.as_token)
        self.assertEquals(stored_service.url, None)
        self.assertEquals(
            stored_service.namespaces[ApplicationService.NS_ALIASES],
            []
        )
        self.assertEquals(
            stored_service.namespaces[ApplicationService.NS_ROOMS],
            []
        )
        self.assertEquals(
            stored_service.namespaces[ApplicationService.NS_USERS],
            []
        )

    @defer.inlineCallbacks
    def test_retrieval_of_all_services(self):
        services = yield self.store.get_app_services()
        self.assertEquals(len(services), 3)
