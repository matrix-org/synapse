# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import logging

from synapse.api.constants import LoginType
from synapse.app.generic_worker import GenericWorkerServer
from synapse.http.server import JsonResource
from synapse.http.site import SynapseRequest
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.rest.client.v2_alpha import register

from tests import unittest
from tests.rest.client.v2_alpha.test_auth import DummyRecaptchaChecker
from tests.server import FakeChannel, render

logger = logging.getLogger(__name__)


class ClientReaderTestCase(unittest.HomeserverTestCase):
    """Base class for tests of the replication streams"""

    servlets = [
        register.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        # build a replication server
        self.server_factory = ReplicationStreamProtocolFactory(hs)
        self.streamer = hs.get_replication_streamer()

        store = hs.get_datastore()
        self.database = store.db

        self.recaptcha_checker = DummyRecaptchaChecker(hs)
        auth_handler = hs.get_auth_handler()
        auth_handler.checkers[LoginType.RECAPTCHA] = self.recaptcha_checker

        self.reactor.lookups["testserv"] = "1.2.3.4"

    def make_worker_hs(self, extra_config={}):
        config = self._get_worker_hs_config()
        config.update(extra_config)

        worker_hs = self.setup_test_homeserver(
            homeserverToUse=GenericWorkerServer, config=config, reactor=self.reactor,
        )

        store = worker_hs.get_datastore()
        store.db._db_pool = self.database._db_pool

        # Register the expected servlets, essentially this is HomeserverTestCase.create_test_json_resource.
        resource = JsonResource(self.hs)

        for servlet in self.servlets:
            servlet(worker_hs, resource)

        # Essentially HomeserverTestCase.render.
        def _render(request):
            render(request, self.resource, self.reactor)

        return worker_hs, _render

    def _get_worker_hs_config(self) -> dict:
        config = self.default_config()
        config["worker_app"] = "synapse.app.client_reader"
        config["worker_replication_host"] = "testserv"
        config["worker_replication_http_port"] = "8765"
        return config

    def test_register_single_worker(self):
        """Test that registration works when using a single client reader worker.
        """
        _, worker_render = self.make_worker_hs()

        request_1, channel_1 = self.make_request(
            "POST",
            "register",
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )  # type: SynapseRequest, FakeChannel
        worker_render(request_1)
        self.assertEqual(request_1.code, 401)

        # Grab the session
        session = channel_1.json_body["session"]

        # also complete the dummy auth
        request_2, channel_2 = self.make_request(
            "POST", "register", {"auth": {"session": session, "type": "m.login.dummy"}}
        )  # type: SynapseRequest, FakeChannel
        worker_render(request_2)
        self.assertEqual(request_2.code, 200)

        # We're given a registered user.
        self.assertEqual(channel_2.json_body["user_id"], "@user:test")

    def test_register_multi_worker(self):
        """Test that registration works when using multiple client reader workers.
        """
        _, worker_render_1 = self.make_worker_hs()
        _, worker_render_2 = self.make_worker_hs()

        request_1, channel_1 = self.make_request(
            "POST",
            "register",
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )  # type: SynapseRequest, FakeChannel
        worker_render_1(request_1)
        self.assertEqual(request_1.code, 401)

        # Grab the session
        session = channel_1.json_body["session"]

        # also complete the dummy auth
        request_2, channel_2 = self.make_request(
            "POST", "register", {"auth": {"session": session, "type": "m.login.dummy"}}
        )  # type: SynapseRequest, FakeChannel
        worker_render_2(request_2)
        self.assertEqual(request_2.code, 200)

        # We're given a registered user.
        self.assertEqual(channel_2.json_body["user_id"], "@user:test")
