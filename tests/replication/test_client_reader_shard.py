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
from synapse.http.site import SynapseRequest
from synapse.rest.client.v2_alpha import register

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.rest.client.v2_alpha.test_auth import DummyRecaptchaChecker
from tests.server import FakeChannel, make_request

logger = logging.getLogger(__name__)


class ClientReaderTestCase(BaseMultiWorkerStreamTestCase):
    """Base class for tests of the replication streams"""

    servlets = [register.register_servlets]

    def prepare(self, reactor, clock, hs):
        self.recaptcha_checker = DummyRecaptchaChecker(hs)
        auth_handler = hs.get_auth_handler()
        auth_handler.checkers[LoginType.RECAPTCHA] = self.recaptcha_checker

    def _get_worker_hs_config(self) -> dict:
        config = self.default_config()
        config["worker_app"] = "synapse.app.client_reader"
        config["worker_replication_host"] = "testserv"
        config["worker_replication_http_port"] = "8765"
        return config

    def test_register_single_worker(self):
        """Test that registration works when using a single client reader worker.
        """
        worker_hs = self.make_worker_hs("synapse.app.client_reader")
        site = self._hs_to_site[worker_hs]

        request_1, channel_1 = make_request(
            self.reactor,
            site,
            "POST",
            "register",
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )  # type: SynapseRequest, FakeChannel
        self.assertEqual(request_1.code, 401)

        # Grab the session
        session = channel_1.json_body["session"]

        # also complete the dummy auth
        request_2, channel_2 = make_request(
            self.reactor,
            site,
            "POST",
            "register",
            {"auth": {"session": session, "type": "m.login.dummy"}},
        )  # type: SynapseRequest, FakeChannel
        self.assertEqual(request_2.code, 200)

        # We're given a registered user.
        self.assertEqual(channel_2.json_body["user_id"], "@user:test")

    def test_register_multi_worker(self):
        """Test that registration works when using multiple client reader workers.
        """
        worker_hs_1 = self.make_worker_hs("synapse.app.client_reader")
        worker_hs_2 = self.make_worker_hs("synapse.app.client_reader")

        site_1 = self._hs_to_site[worker_hs_1]
        request_1, channel_1 = make_request(
            self.reactor,
            site_1,
            "POST",
            "register",
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )  # type: SynapseRequest, FakeChannel
        self.assertEqual(request_1.code, 401)

        # Grab the session
        session = channel_1.json_body["session"]

        # also complete the dummy auth
        site_2 = self._hs_to_site[worker_hs_2]
        request_2, channel_2 = make_request(
            self.reactor,
            site_2,
            "POST",
            "register",
            {"auth": {"session": session, "type": "m.login.dummy"}},
        )  # type: SynapseRequest, FakeChannel
        self.assertEqual(request_2.code, 200)

        # We're given a registered user.
        self.assertEqual(channel_2.json_body["user_id"], "@user:test")
