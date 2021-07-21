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

from synapse.rest.client.v2_alpha import register

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.server import FakeChannel, make_request
from tests.unittest import override_config

logger = logging.getLogger(__name__)


class WorkerAuthenticationTestCase(BaseMultiWorkerStreamTestCase):
    """Test the authentication of HTTP calls between workers."""

    servlets = [register.register_servlets]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        # This isn't a real configuration option but is used to provide the main
        # homeserver and worker homeserver different options.
        main_replication_secret = config.pop("main_replication_secret", None)
        if main_replication_secret:
            config["worker_replication_secret"] = main_replication_secret
        return self.setup_test_homeserver(config=config)

    def _get_worker_hs_config(self) -> dict:
        config = self.default_config()
        config["worker_app"] = "synapse.app.client_reader"
        config["worker_replication_host"] = "testserv"
        config["worker_replication_http_port"] = "8765"

        return config

    def _test_register(self) -> FakeChannel:
        """Run the actual test:

        1. Create a worker homeserver.
        2. Start registration by providing a user/password.
        3. Complete registration by providing dummy auth (this hits the main synapse).
        4. Return the final request.

        """
        worker_hs = self.make_worker_hs("synapse.app.client_reader")
        site = self._hs_to_site[worker_hs]

        channel_1 = make_request(
            self.reactor,
            site,
            "POST",
            "register",
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )
        self.assertEqual(channel_1.code, 401)

        # Grab the session
        session = channel_1.json_body["session"]

        # also complete the dummy auth
        return make_request(
            self.reactor,
            site,
            "POST",
            "register",
            {"auth": {"session": session, "type": "m.login.dummy"}},
        )

    def test_no_auth(self):
        """With no authentication the request should finish."""
        channel = self._test_register()
        self.assertEqual(channel.code, 200)

        # We're given a registered user.
        self.assertEqual(channel.json_body["user_id"], "@user:test")

    @override_config({"main_replication_secret": "my-secret"})
    def test_missing_auth(self):
        """If the main process expects a secret that is not provided, an error results."""
        channel = self._test_register()
        self.assertEqual(channel.code, 500)

    @override_config(
        {
            "main_replication_secret": "my-secret",
            "worker_replication_secret": "wrong-secret",
        }
    )
    def test_unauthorized(self):
        """If the main process receives the wrong secret, an error results."""
        channel = self._test_register()
        self.assertEqual(channel.code, 500)

    @override_config({"worker_replication_secret": "my-secret"})
    def test_authorized(self):
        """The request should finish when the worker provides the authentication header."""
        channel = self._test_register()
        self.assertEqual(channel.code, 200)

        # We're given a registered user.
        self.assertEqual(channel.json_body["user_id"], "@user:test")
