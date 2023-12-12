# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus

from synapse.rest.client import auth_issuer

from tests.unittest import HomeserverTestCase, override_config, skip_unless
from tests.utils import HAS_AUTHLIB

ISSUER = "https://account.example.com/"


class AuthIssuerTestCase(HomeserverTestCase):
    servlets = [
        auth_issuer.register_servlets,
    ]

    def test_returns_404_when_msc3861_disabled(self) -> None:
        # Make an unauthenticated request for the discovery info.
        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/org.matrix.msc2965/auth_issuer",
        )
        self.assertEqual(channel.code, HTTPStatus.NOT_FOUND)

    @skip_unless(HAS_AUTHLIB, "requires authlib")
    @override_config(
        {
            "disable_registration": True,
            "experimental_features": {
                "msc3861": {
                    "enabled": True,
                    "issuer": ISSUER,
                    "client_id": "David Lister",
                    "client_auth_method": "client_secret_post",
                    "client_secret": "Who shot Mister Burns?",
                }
            },
        }
    )
    def test_returns_issuer_when_oidc_enabled(self) -> None:
        # Make an unauthenticated request for the discovery info.
        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/org.matrix.msc2965/auth_issuer",
        )
        self.assertEqual(channel.code, HTTPStatus.OK)
        self.assertEqual(channel.json_body, {"issuer": ISSUER})
