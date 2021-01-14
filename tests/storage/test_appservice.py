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
import json
import os
import tempfile

from mock import Mock

import yaml

from twisted.internet import defer

from synapse.appservice import ApplicationService, ApplicationServiceState
from synapse.config._base import ConfigError
from synapse.storage.database import DatabasePool, make_conn
from synapse.storage.databases.main.appservice import (
    ApplicationServiceStore,
    ApplicationServiceTransactionStore,
)

from tests import unittest
from tests.test_utils import make_awaitable
from tests.utils import setup_test_homeserver


class ApplicationServiceStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.as_yaml_files = []
        hs = yield setup_test_homeserver(
            self.addCleanup, federation_sender=Mock(), federation_client=Mock()
        )

        hs.config.app_service_config_files = self.as_yaml_files
        hs.config.caches.event_cache_size = 1
        hs.config.password_providers = []

        self.as_token = "token1"
        self.as_url = "some_url"
        self.as_id = "as1"
        self._add_appservice(
            self.as_token, self.as_id, self.as_url, "some_hs_token", "bob"
        )
        self._add_appservice("token2", "as2", "some_url", "some_hs_token", "bob")
        self._add_appservice("token3", "as3", "some_url", "some_hs_token", "bob")
        # must be done after inserts
        database = hs.get_datastores().databases[0]
        self.store = ApplicationServiceStore(
            database, make_conn(database._database_config, database.engine, "test"), hs
        )

    def tearDown(self):
        # TODO: suboptimal that we need to create files for tests!
        for f in self.as_yaml_files:
            try:
                os.remove(f)
            except Exception:
                pass

    def _add_appservice(self, as_token, id, url, hs_token, sender):
        as_yaml = {
            "url": url,
            "as_token": as_token,
            "hs_token": hs_token,
            "id": id,
            "sender_localpart": sender,
            "namespaces": {},
        }
        # use the token as the filename
        with open(as_token, "w") as outfile:
            outfile.write(yaml.dump(as_yaml))
            self.as_yaml_files.append(as_token)

    def test_retrieve_unknown_service_token(self):
        service = self.store.get_app_service_by_token("invalid_token")
        self.assertEquals(service, None)

    def test_retrieval_of_service(self):
        stored_service = self.store.get_app_service_by_token(self.as_token)
        self.assertEquals(stored_service.token, self.as_token)
        self.assertEquals(stored_service.id, self.as_id)
        self.assertEquals(stored_service.url, self.as_url)
        self.assertEquals(stored_service.namespaces[ApplicationService.NS_ALIASES], [])
        self.assertEquals(stored_service.namespaces[ApplicationService.NS_ROOMS], [])
        self.assertEquals(stored_service.namespaces[ApplicationService.NS_USERS], [])

    def test_retrieval_of_all_services(self):
        services = self.store.get_app_services()
        self.assertEquals(len(services), 3)


class ApplicationServiceTransactionStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.as_yaml_files = []

        hs = yield setup_test_homeserver(
            self.addCleanup, federation_sender=Mock(), federation_client=Mock()
        )

        hs.config.app_service_config_files = self.as_yaml_files
        hs.config.caches.event_cache_size = 1
        hs.config.password_providers = []

        self.as_list = [
            {"token": "token1", "url": "https://matrix-as.org", "id": "id_1"},
            {"token": "alpha_tok", "url": "https://alpha.com", "id": "id_alpha"},
            {"token": "beta_tok", "url": "https://beta.com", "id": "id_beta"},
            {"token": "gamma_tok", "url": "https://gamma.com", "id": "id_gamma"},
        ]
        for s in self.as_list:
            yield self._add_service(s["url"], s["token"], s["id"])

        self.as_yaml_files = []

        # We assume there is only one database in these tests
        database = hs.get_datastores().databases[0]
        self.db_pool = database._db_pool
        self.engine = database.engine

        db_config = hs.config.get_single_database()
        self.store = TestTransactionStore(
            database, make_conn(db_config, self.engine, "test"), hs
        )

    def _add_service(self, url, as_token, id):
        as_yaml = {
            "url": url,
            "as_token": as_token,
            "hs_token": "something",
            "id": id,
            "sender_localpart": "a_sender",
            "namespaces": {},
        }
        # use the token as the filename
        with open(as_token, "w") as outfile:
            outfile.write(yaml.dump(as_yaml))
            self.as_yaml_files.append(as_token)

    def _set_state(self, id, state, txn=None):
        return self.db_pool.runOperation(
            self.engine.convert_param_style(
                "INSERT INTO application_services_state(as_id, state, last_txn) "
                "VALUES(?,?,?)"
            ),
            (id, state, txn),
        )

    def _insert_txn(self, as_id, txn_id, events):
        return self.db_pool.runOperation(
            self.engine.convert_param_style(
                "INSERT INTO application_services_txns(as_id, txn_id, event_ids) "
                "VALUES(?,?,?)"
            ),
            (as_id, txn_id, json.dumps([e.event_id for e in events])),
        )

    def _set_last_txn(self, as_id, txn_id):
        return self.db_pool.runOperation(
            self.engine.convert_param_style(
                "INSERT INTO application_services_state(as_id, last_txn, state) "
                "VALUES(?,?,?)"
            ),
            (as_id, txn_id, ApplicationServiceState.UP),
        )

    @defer.inlineCallbacks
    def test_get_appservice_state_none(self):
        service = Mock(id="999")
        state = yield defer.ensureDeferred(self.store.get_appservice_state(service))
        self.assertEquals(None, state)

    @defer.inlineCallbacks
    def test_get_appservice_state_up(self):
        yield self._set_state(self.as_list[0]["id"], ApplicationServiceState.UP)
        service = Mock(id=self.as_list[0]["id"])
        state = yield defer.ensureDeferred(self.store.get_appservice_state(service))
        self.assertEquals(ApplicationServiceState.UP, state)

    @defer.inlineCallbacks
    def test_get_appservice_state_down(self):
        yield self._set_state(self.as_list[0]["id"], ApplicationServiceState.UP)
        yield self._set_state(self.as_list[1]["id"], ApplicationServiceState.DOWN)
        yield self._set_state(self.as_list[2]["id"], ApplicationServiceState.DOWN)
        service = Mock(id=self.as_list[1]["id"])
        state = yield defer.ensureDeferred(self.store.get_appservice_state(service))
        self.assertEquals(ApplicationServiceState.DOWN, state)

    @defer.inlineCallbacks
    def test_get_appservices_by_state_none(self):
        services = yield defer.ensureDeferred(
            self.store.get_appservices_by_state(ApplicationServiceState.DOWN)
        )
        self.assertEquals(0, len(services))

    @defer.inlineCallbacks
    def test_set_appservices_state_down(self):
        service = Mock(id=self.as_list[1]["id"])
        yield defer.ensureDeferred(
            self.store.set_appservice_state(service, ApplicationServiceState.DOWN)
        )
        rows = yield self.db_pool.runQuery(
            self.engine.convert_param_style(
                "SELECT as_id FROM application_services_state WHERE state=?"
            ),
            (ApplicationServiceState.DOWN,),
        )
        self.assertEquals(service.id, rows[0][0])

    @defer.inlineCallbacks
    def test_set_appservices_state_multiple_up(self):
        service = Mock(id=self.as_list[1]["id"])
        yield defer.ensureDeferred(
            self.store.set_appservice_state(service, ApplicationServiceState.UP)
        )
        yield defer.ensureDeferred(
            self.store.set_appservice_state(service, ApplicationServiceState.DOWN)
        )
        yield defer.ensureDeferred(
            self.store.set_appservice_state(service, ApplicationServiceState.UP)
        )
        rows = yield self.db_pool.runQuery(
            self.engine.convert_param_style(
                "SELECT as_id FROM application_services_state WHERE state=?"
            ),
            (ApplicationServiceState.UP,),
        )
        self.assertEquals(service.id, rows[0][0])

    @defer.inlineCallbacks
    def test_create_appservice_txn_first(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [Mock(event_id="e1"), Mock(event_id="e2")]
        txn = yield defer.ensureDeferred(
            self.store.create_appservice_txn(service, events, [])
        )
        self.assertEquals(txn.id, 1)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_create_appservice_txn_older_last_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [Mock(event_id="e1"), Mock(event_id="e2")]
        yield self._set_last_txn(service.id, 9643)  # AS is falling behind
        yield self._insert_txn(service.id, 9644, events)
        yield self._insert_txn(service.id, 9645, events)
        txn = yield defer.ensureDeferred(
            self.store.create_appservice_txn(service, events, [])
        )
        self.assertEquals(txn.id, 9646)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_create_appservice_txn_up_to_date_last_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [Mock(event_id="e1"), Mock(event_id="e2")]
        yield self._set_last_txn(service.id, 9643)
        txn = yield defer.ensureDeferred(
            self.store.create_appservice_txn(service, events, [])
        )
        self.assertEquals(txn.id, 9644)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_create_appservice_txn_up_fuzzing(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [Mock(event_id="e1"), Mock(event_id="e2")]
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

        txn = yield defer.ensureDeferred(
            self.store.create_appservice_txn(service, events, [])
        )
        self.assertEquals(txn.id, 9644)
        self.assertEquals(txn.events, events)
        self.assertEquals(txn.service, service)

    @defer.inlineCallbacks
    def test_complete_appservice_txn_first_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [Mock(event_id="e1"), Mock(event_id="e2")]
        txn_id = 1

        yield self._insert_txn(service.id, txn_id, events)
        yield defer.ensureDeferred(
            self.store.complete_appservice_txn(txn_id=txn_id, service=service)
        )

        res = yield self.db_pool.runQuery(
            self.engine.convert_param_style(
                "SELECT last_txn FROM application_services_state WHERE as_id=?"
            ),
            (service.id,),
        )
        self.assertEquals(1, len(res))
        self.assertEquals(txn_id, res[0][0])

        res = yield self.db_pool.runQuery(
            self.engine.convert_param_style(
                "SELECT * FROM application_services_txns WHERE txn_id=?"
            ),
            (txn_id,),
        )
        self.assertEquals(0, len(res))

    @defer.inlineCallbacks
    def test_complete_appservice_txn_existing_in_state_table(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [Mock(event_id="e1"), Mock(event_id="e2")]
        txn_id = 5
        yield self._set_last_txn(service.id, 4)
        yield self._insert_txn(service.id, txn_id, events)
        yield defer.ensureDeferred(
            self.store.complete_appservice_txn(txn_id=txn_id, service=service)
        )

        res = yield self.db_pool.runQuery(
            self.engine.convert_param_style(
                "SELECT last_txn, state FROM application_services_state WHERE as_id=?"
            ),
            (service.id,),
        )
        self.assertEquals(1, len(res))
        self.assertEquals(txn_id, res[0][0])
        self.assertEquals(ApplicationServiceState.UP, res[0][1])

        res = yield self.db_pool.runQuery(
            self.engine.convert_param_style(
                "SELECT * FROM application_services_txns WHERE txn_id=?"
            ),
            (txn_id,),
        )
        self.assertEquals(0, len(res))

    @defer.inlineCallbacks
    def test_get_oldest_unsent_txn_none(self):
        service = Mock(id=self.as_list[0]["id"])

        txn = yield defer.ensureDeferred(self.store.get_oldest_unsent_txn(service))
        self.assertEquals(None, txn)

    @defer.inlineCallbacks
    def test_get_oldest_unsent_txn(self):
        service = Mock(id=self.as_list[0]["id"])
        events = [Mock(event_id="e1"), Mock(event_id="e2")]
        other_events = [Mock(event_id="e5"), Mock(event_id="e6")]

        # we aren't testing store._base stuff here, so mock this out
        self.store.get_events_as_list = Mock(return_value=make_awaitable(events))

        yield self._insert_txn(self.as_list[1]["id"], 9, other_events)
        yield self._insert_txn(service.id, 10, events)
        yield self._insert_txn(service.id, 11, other_events)
        yield self._insert_txn(service.id, 12, other_events)

        txn = yield defer.ensureDeferred(self.store.get_oldest_unsent_txn(service))
        self.assertEquals(service, txn.service)
        self.assertEquals(10, txn.id)
        self.assertEquals(events, txn.events)

    @defer.inlineCallbacks
    def test_get_appservices_by_state_single(self):
        yield self._set_state(self.as_list[0]["id"], ApplicationServiceState.DOWN)
        yield self._set_state(self.as_list[1]["id"], ApplicationServiceState.UP)

        services = yield defer.ensureDeferred(
            self.store.get_appservices_by_state(ApplicationServiceState.DOWN)
        )
        self.assertEquals(1, len(services))
        self.assertEquals(self.as_list[0]["id"], services[0].id)

    @defer.inlineCallbacks
    def test_get_appservices_by_state_multiple(self):
        yield self._set_state(self.as_list[0]["id"], ApplicationServiceState.DOWN)
        yield self._set_state(self.as_list[1]["id"], ApplicationServiceState.UP)
        yield self._set_state(self.as_list[2]["id"], ApplicationServiceState.DOWN)
        yield self._set_state(self.as_list[3]["id"], ApplicationServiceState.UP)

        services = yield defer.ensureDeferred(
            self.store.get_appservices_by_state(ApplicationServiceState.DOWN)
        )
        self.assertEquals(2, len(services))
        self.assertEquals(
            {self.as_list[2]["id"], self.as_list[0]["id"]},
            {services[0].id, services[1].id},
        )


class ApplicationServiceStoreTypeStreamIds(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()
        return hs

    def prepare(self, hs, reactor, clock):
        self.service = Mock(id="foo")
        self.store = self.hs.get_datastore()
        self.get_success(self.store.set_appservice_state(self.service, "up"))

    def test_get_type_stream_id_for_appservice_no_value(self):
        value = self.get_success(
            self.store.get_type_stream_id_for_appservice(self.service, "read_receipt")
        )
        self.assertEquals(value, 0)

        value = self.get_success(
            self.store.get_type_stream_id_for_appservice(self.service, "presence")
        )
        self.assertEquals(value, 0)

    def test_get_type_stream_id_for_appservice_invalid_type(self):
        self.get_failure(
            self.store.get_type_stream_id_for_appservice(self.service, "foobar"),
            ValueError,
        )

    def test_set_type_stream_id_for_appservice(self):
        read_receipt_value = 1024
        self.get_success(
            self.store.set_type_stream_id_for_appservice(
                self.service, "read_receipt", read_receipt_value
            )
        )
        result = self.get_success(
            self.store.get_type_stream_id_for_appservice(self.service, "read_receipt")
        )
        self.assertEqual(result, read_receipt_value)

        self.get_success(
            self.store.set_type_stream_id_for_appservice(
                self.service, "presence", read_receipt_value
            )
        )
        result = self.get_success(
            self.store.get_type_stream_id_for_appservice(self.service, "presence")
        )
        self.assertEqual(result, read_receipt_value)

    def test_set_type_stream_id_for_appservice_invalid_type(self):
        self.get_failure(
            self.store.set_type_stream_id_for_appservice(self.service, "foobar", 1024),
            ValueError,
        )


# required for ApplicationServiceTransactionStoreTestCase tests
class TestTransactionStore(ApplicationServiceTransactionStore, ApplicationServiceStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)


class ApplicationServiceStoreConfigTestCase(unittest.TestCase):
    def _write_config(self, suffix, **kwargs):
        vals = {
            "id": "id" + suffix,
            "url": "url" + suffix,
            "as_token": "as_token" + suffix,
            "hs_token": "hs_token" + suffix,
            "sender_localpart": "sender_localpart" + suffix,
            "namespaces": {},
        }
        vals.update(kwargs)

        _, path = tempfile.mkstemp(prefix="as_config")
        with open(path, "w") as f:
            f.write(yaml.dump(vals))
        return path

    @defer.inlineCallbacks
    def test_unique_works(self):
        f1 = self._write_config(suffix="1")
        f2 = self._write_config(suffix="2")

        hs = yield setup_test_homeserver(
            self.addCleanup, federation_sender=Mock(), federation_client=Mock()
        )

        hs.config.app_service_config_files = [f1, f2]
        hs.config.caches.event_cache_size = 1
        hs.config.password_providers = []

        database = hs.get_datastores().databases[0]
        ApplicationServiceStore(
            database, make_conn(database._database_config, database.engine, "test"), hs
        )

    @defer.inlineCallbacks
    def test_duplicate_ids(self):
        f1 = self._write_config(id="id", suffix="1")
        f2 = self._write_config(id="id", suffix="2")

        hs = yield setup_test_homeserver(
            self.addCleanup, federation_sender=Mock(), federation_client=Mock()
        )

        hs.config.app_service_config_files = [f1, f2]
        hs.config.caches.event_cache_size = 1
        hs.config.password_providers = []

        with self.assertRaises(ConfigError) as cm:
            database = hs.get_datastores().databases[0]
            ApplicationServiceStore(
                database,
                make_conn(database._database_config, database.engine, "test"),
                hs,
            )

        e = cm.exception
        self.assertIn(f1, str(e))
        self.assertIn(f2, str(e))
        self.assertIn("id", str(e))

    @defer.inlineCallbacks
    def test_duplicate_as_tokens(self):
        f1 = self._write_config(as_token="as_token", suffix="1")
        f2 = self._write_config(as_token="as_token", suffix="2")

        hs = yield setup_test_homeserver(
            self.addCleanup, federation_sender=Mock(), federation_client=Mock()
        )

        hs.config.app_service_config_files = [f1, f2]
        hs.config.caches.event_cache_size = 1
        hs.config.password_providers = []

        with self.assertRaises(ConfigError) as cm:
            database = hs.get_datastores().databases[0]
            ApplicationServiceStore(
                database,
                make_conn(database._database_config, database.engine, "test"),
                hs,
            )

        e = cm.exception
        self.assertIn(f1, str(e))
        self.assertIn(f2, str(e))
        self.assertIn("as_token", str(e))
