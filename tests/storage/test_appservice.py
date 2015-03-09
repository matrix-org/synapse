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

from synapse.appservice import ApplicationService, ApplicationServiceState
from synapse.server import HomeServer
from synapse.storage.appservice import (
    ApplicationServiceStore, ApplicationServiceTransactionStore
)

import json
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
        user_regex = [
            {"regex": "@foobar_.*:matrix.org", "exclusive": True}
        ]
        alias_regex = [
            {"regex": "#foobar_.*:matrix.org", "exclusive": False}
        ]
        room_regex = [

        ]
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


class ApplicationServiceTransactionStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        self.db_pool = SQLiteMemoryDbPool()
        yield self.db_pool.prepare()
        hs = HomeServer(
            "test", db_pool=self.db_pool, clock=MockClock(), config=Mock()
        )
        self.as_list = [
            {
                "token": "token1",
                "url": "https://matrix-as.org",
                "id": 3
            },
            {
                "token": "alpha_tok",
                "url": "https://alpha.com",
                "id": 5
            },
            {
                "token": "beta_tok",
                "url": "https://beta.com",
                "id": 6
            },
            {
                "token": "delta_tok",
                "url": "https://delta.com",
                "id": 7
            },
        ]
        for s in self.as_list:
            yield self._add_service(s["id"], s["url"], s["token"])
        self.store = TestTransactionStore(hs)

    def _add_service(self, as_id, url, token):
        return self.db_pool.runQuery(
            "INSERT INTO application_services(id, url, token) VALUES(?,?,?)",
            (as_id, url, token)
        )

    def _set_state(self, id, state, txn=None):
        return self.db_pool.runQuery(
            "INSERT INTO application_services_state(as_id, state, last_txn) "
            "VALUES(?,?,?)",
            (id, state, txn)
        )

    def _insert_txn(self, as_id, txn_id, content):
        return self.db_pool.runQuery(
            "INSERT INTO application_services_txns(as_id, txn_id, content) "
            "VALUES(?,?,?)",
            (as_id, txn_id, json.dumps(content))
        )

    def _set_last_txn(self, as_id, txn_id):
        return self.db_pool.runQuery(
            "INSERT INTO application_services_state(as_id, last_txn, state) "
            "VALUES(?,?,?)",
            (as_id, txn_id, ApplicationServiceState.UP)
        )

    @defer.inlineCallbacks
    def test_get_appservice_state_none(self):
        service = Mock(id=999)
        state = yield self.store.get_appservice_state(service)
        self.assertEquals(None, state)

    @defer.inlineCallbacks
    def test_get_appservice_state_up(self):
        yield self._set_state(
            self.as_list[0]["id"], ApplicationServiceState.UP
        )
        service = Mock(id=self.as_list[0]["id"])
        state = yield self.store.get_appservice_state(service)
        self.assertEquals(ApplicationServiceState.UP, state)

    @defer.inlineCallbacks
    def test_get_appservice_state_down(self):
        yield self._set_state(
            self.as_list[0]["id"], ApplicationServiceState.UP
        )
        yield self._set_state(
            self.as_list[1]["id"], ApplicationServiceState.DOWN
        )
        yield self._set_state(
            self.as_list[2]["id"], ApplicationServiceState.DOWN
        )
        service = Mock(id=self.as_list[1]["id"])
        state = yield self.store.get_appservice_state(service)
        self.assertEquals(ApplicationServiceState.DOWN, state)

    @defer.inlineCallbacks
    def test_get_appservices_by_state_none(self):
        services = yield self.store.get_appservices_by_state(
            ApplicationServiceState.DOWN
        )
        self.assertEquals(0, len(services))

    @defer.inlineCallbacks
    def test_set_appservices_state_down(self):
        service = Mock(id=self.as_list[1]["id"])
        yield self.store.set_appservice_state(
            service,
            ApplicationServiceState.DOWN
        )
        rows = yield self.db_pool.runQuery(
            "SELECT as_id FROM application_services_state WHERE state=?",
            (ApplicationServiceState.DOWN,)
        )
        self.assertEquals(service.id, rows[0][0])

    @defer.inlineCallbacks
    def test_set_appservices_state_multiple_up(self):
        service = Mock(id=self.as_list[1]["id"])
        yield self.store.set_appservice_state(
            service,
            ApplicationServiceState.UP
        )
        yield self.store.set_appservice_state(
            service,
            ApplicationServiceState.DOWN
        )
        yield self.store.set_appservice_state(
            service,
            ApplicationServiceState.UP
        )
        rows = yield self.db_pool.runQuery(
            "SELECT as_id FROM application_services_state WHERE state=?",
            (ApplicationServiceState.UP,)
        )
        self.assertEquals(service.id, rows[0][0])

    @defer.inlineCallbacks
    def test_create_appservice_txn_first(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [{"type": "nothing"}, {"type": "here"}]
        txn = yield self.store.create_appservice_txn(service, events)
        self.assertEquals(txn.id, 1)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_create_appservice_txn_older_last_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [{"type": "nothing"}, {"type": "here"}]
        yield self._set_last_txn(service.id, 9643)  # AS is falling behind
        yield self._insert_txn(service.id, 9644, events)
        yield self._insert_txn(service.id, 9645, events)
        txn = yield self.store.create_appservice_txn(service, events)
        self.assertEquals(txn.id, 9646)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_create_appservice_txn_up_to_date_last_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [{"type": "nothing"}, {"type": "here"}]
        yield self._set_last_txn(service.id, 9643)
        txn = yield self.store.create_appservice_txn(service, events)
        self.assertEquals(txn.id, 9644)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_create_appservice_txn_up_fuzzing(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [{"type": "nothing"}, {"type": "here"}]
        yield self._set_last_txn(service.id, 9643)

        # dump in rows with higher IDs to make sure the queries aren't wrong.
        yield self._set_last_txn(self.as_list[1]["id"], 119643)
        yield self._set_last_txn(self.as_list[2]["id"], 9)
        yield self._set_last_txn(self.as_list[3]["id"], 9643)
        yield self._insert_txn(self.as_list[1]["id"], 119644, events)
        yield self._insert_txn(self.as_list[1]["id"], 119645, events)
        yield self._insert_txn(self.as_list[1]["id"], 119646, events)
        yield self._insert_txn(self.as_list[2]["id"], 10, events)
        yield self._insert_txn(self.as_list[3]["id"], 9643, events)

        txn = yield self.store.create_appservice_txn(service, events)
        self.assertEquals(txn.id, 9644)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_complete_appservice_txn_first_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [{"foo": "bar"}]
        txn_id = 1

        yield self._insert_txn(service.id, txn_id, events)
        yield self.store.complete_appservice_txn(txn_id=txn_id, service=service)

        res = yield self.db_pool.runQuery(
            "SELECT last_txn FROM application_services_state WHERE as_id=?",
            (service.id,)
        )
        self.assertEquals(1, len(res))
        self.assertEquals(str(txn_id), res[0][0])

        res = yield self.db_pool.runQuery(
            "SELECT * FROM application_services_txns WHERE txn_id=?",
            (txn_id,)
        )
        self.assertEquals(0, len(res))

    @defer.inlineCallbacks
    def test_complete_appservice_txn_existing_in_state_table(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [{"foo": "bar"}]
        txn_id = 5
        yield self._set_last_txn(service.id, 4)
        yield self._insert_txn(service.id, txn_id, events)
        yield self.store.complete_appservice_txn(txn_id=txn_id, service=service)

        res = yield self.db_pool.runQuery(
            "SELECT last_txn, state FROM application_services_state WHERE "
            "as_id=?",
            (service.id,)
        )
        self.assertEquals(1, len(res))
        self.assertEquals(str(txn_id), res[0][0])
        self.assertEquals(ApplicationServiceState.UP, res[0][1])

        res = yield self.db_pool.runQuery(
            "SELECT * FROM application_services_txns WHERE txn_id=?",
            (txn_id,)
        )
        self.assertEquals(0, len(res))

    @defer.inlineCallbacks
    def test_get_oldest_unsent_txn_none(self):
        service = Mock(id=self.as_list[0]["id"])

        txn = yield self.store.get_oldest_unsent_txn(service)
        self.assertEquals(None, txn)

    @defer.inlineCallbacks
    def test_get_oldest_unsent_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [{"type": "nothing"}, {"type": "here"}]

        yield self._insert_txn(self.as_list[1]["id"], 9, {"badger": "mushroom"})
        yield self._insert_txn(service.id, 10, events)
        yield self._insert_txn(service.id, 11, [{"foo":"bar"}])
        yield self._insert_txn(service.id, 12, [{"argh":"bargh"}])

        txn = yield self.store.get_oldest_unsent_txn(service)
        self.assertEquals(service, txn.service)
        self.assertEquals(10, txn.id)
        self.assertEquals(events, txn.events)

    @defer.inlineCallbacks
    def test_get_appservices_by_state_single(self):
        yield self._set_state(
            self.as_list[0]["id"], ApplicationServiceState.DOWN
        )
        yield self._set_state(
            self.as_list[1]["id"], ApplicationServiceState.UP
        )

        services = yield self.store.get_appservices_by_state(
            ApplicationServiceState.DOWN
        )
        self.assertEquals(1, len(services))
        self.assertEquals(self.as_list[0]["id"], services[0].id)

    @defer.inlineCallbacks
    def test_get_appservices_by_state_multiple(self):
        yield self._set_state(
            self.as_list[0]["id"], ApplicationServiceState.DOWN
        )
        yield self._set_state(
            self.as_list[1]["id"], ApplicationServiceState.UP
        )
        yield self._set_state(
            self.as_list[2]["id"], ApplicationServiceState.DOWN
        )
        yield self._set_state(
            self.as_list[3]["id"], ApplicationServiceState.UP
        )

        services = yield self.store.get_appservices_by_state(
            ApplicationServiceState.DOWN
        )
        self.assertEquals(2, len(services))
        self.assertEquals(self.as_list[2]["id"], services[0].id)
        self.assertEquals(self.as_list[0]["id"], services[1].id)


# required for ApplicationServiceTransactionStoreTestCase tests
class TestTransactionStore(ApplicationServiceTransactionStore,
                           ApplicationServiceStore):

    def __init__(self, hs):
        super(TestTransactionStore, self).__init__(hs)
