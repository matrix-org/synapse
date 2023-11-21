# Copyright 2023 Matrix.org Foundation C.I.C.
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

import os
from unittest.mock import Mock

from synapse.config import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.module_api import ModuleApi
from synapse.types import JsonDict

from tests.server import get_clock, setup_test_homeserver
from tests.unittest import TestCase, skip_unless
from tests.utils import HAS_AUTHLIB, default_config

# These are a few constants that are used as config parameters in the tests.
SERVER_NAME = "test"
ISSUER = "https://issuer/"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
BASE_URL = "https://synapse/"


class CustomAuthModule:
    """A module which registers a password auth provider."""

    @staticmethod
    def parse_config(config: JsonDict) -> None:
        pass

    def __init__(self, config: None, api: ModuleApi):
        api.register_password_auth_provider_callbacks(
            auth_checkers={("m.login.password", ("password",)): Mock()},
        )


@skip_unless(HAS_AUTHLIB, "requires authlib")
class MSC3861OAuthDelegation(TestCase):
    """Test that the Homeserver fails to initialize if the config is invalid."""

    def setUp(self) -> None:
        self.config_dict: JsonDict = {
            **default_config("test"),
            "public_baseurl": BASE_URL,
            "enable_registration": False,
            "experimental_features": {
                "msc3861": {
                    "enabled": True,
                    "issuer": ISSUER,
                    "client_id": CLIENT_ID,
                    "client_auth_method": "client_secret_post",
                    "client_secret": CLIENT_SECRET,
                }
            },
        }

    def parse_config(self) -> HomeServerConfig:
        config = HomeServerConfig()
        config.parse_config_dict(self.config_dict, "", "")
        return config

    def test_client_secret_post_works(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="client_secret_post",
            client_secret=CLIENT_SECRET,
        )

        self.parse_config()

    def test_client_secret_post_requires_client_secret(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="client_secret_post",
            client_secret=None,
        )

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_client_secret_basic_works(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="client_secret_basic",
            client_secret=CLIENT_SECRET,
        )

        self.parse_config()

    def test_client_secret_basic_requires_client_secret(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="client_secret_basic",
            client_secret=None,
        )

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_client_secret_jwt_works(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="client_secret_jwt",
            client_secret=CLIENT_SECRET,
        )

        self.parse_config()

    def test_client_secret_jwt_requires_client_secret(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="client_secret_jwt",
            client_secret=None,
        )

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_invalid_client_auth_method(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="invalid",
        )

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_private_key_jwt_requires_jwk(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="private_key_jwt",
        )

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_private_key_jwt_works(self) -> None:
        self.config_dict["experimental_features"]["msc3861"].update(
            client_auth_method="private_key_jwt",
            jwk={
                "p": "-frVdP_tZ-J_nIR6HNMDq1N7aunwm51nAqNnhqIyuA8ikx7LlQED1tt2LD3YEvYyW8nxE2V95HlCRZXQPMiRJBFOsbmYkzl2t-MpavTaObB_fct_JqcRtdXddg4-_ihdjRDwUOreq_dpWh6MIKsC3UyekfkHmeEJg5YpOTL15j8",
                "kty": "RSA",
                "q": "oFw-Enr_YozQB1ab-kawn4jY3yHi8B1nSmYT0s8oTCflrmps5BFJfCkHL5ij3iY15z0o2m0N-jjB1oSJ98O4RayEEYNQlHnTNTl0kRIWzpoqblHUIxVcahIpP_xTovBJzwi8XXoLGqHOOMA-r40LSyVgP2Ut8D9qBwV6_UfT0LU",
                "d": "WFkDPYo4b4LIS64D_QtQfGGuAObPvc3HFfp9VZXyq3SJR58XZRHE0jqtlEMNHhOTgbMYS3w8nxPQ_qVzY-5hs4fIanwvB64mAoOGl0qMHO65DTD_WsGFwzYClJPBVniavkLE2Hmpu8IGe6lGliN8vREC6_4t69liY-XcN_ECboVtC2behKkLOEASOIMuS7YcKAhTJFJwkl1dqDlliEn5A4u4xy7nuWQz3juB1OFdKlwGA5dfhDNglhoLIwNnkLsUPPFO-WB5ZNEW35xxHOToxj4bShvDuanVA6mJPtTKjz0XibjB36bj_nF_j7EtbE2PdGJ2KevAVgElR4lqS4ISgQ",
                "e": "AQAB",
                "kid": "test",
                "qi": "cPfNk8l8W5exVNNea4d7QZZ8Qr8LgHghypYAxz8PQh1fNa8Ya1SNUDVzC2iHHhszxxA0vB9C7jGze8dBrvnzWYF1XvQcqNIVVgHhD57R1Nm3dj2NoHIKe0Cu4bCUtP8xnZQUN4KX7y4IIcgRcBWG1hT6DEYZ4BxqicnBXXNXAUI",
                "dp": "dKlMHvslV1sMBQaKWpNb3gPq0B13TZhqr3-E2_8sPlvJ3fD8P4CmwwnOn50JDuhY3h9jY5L06sBwXjspYISVv8hX-ndMLkEeF3lrJeA5S70D8rgakfZcPIkffm3tlf1Ok3v5OzoxSv3-67Df4osMniyYwDUBCB5Oq1tTx77xpU8",
                "dq": "S4ooU1xNYYcjl9FcuJEEMqKsRrAXzzSKq6laPTwIp5dDwt2vXeAm1a4eDHXC-6rUSZGt5PbqVqzV4s-cjnJMI8YYkIdjNg4NSE1Ac_YpeDl3M3Colb5CQlU7yUB7xY2bt0NOOFp9UJZYJrOo09mFMGjy5eorsbitoZEbVqS3SuE",
                "n": "nJbYKqFwnURKimaviyDFrNLD3gaKR1JW343Qem25VeZxoMq1665RHVoO8n1oBm4ClZdjIiZiVdpyqzD5-Ow12YQgQEf1ZHP3CCcOQQhU57Rh5XvScTe5IxYVkEW32IW2mp_CJ6WfjYpfeL4azarVk8H3Vr59d1rSrKTVVinVdZer9YLQyC_rWAQNtHafPBMrf6RYiNGV9EiYn72wFIXlLlBYQ9Fx7bfe1PaL6qrQSsZP3_rSpuvVdLh1lqGeCLR0pyclA9uo5m2tMyCXuuGQLbA_QJm5xEc7zd-WFdux2eXF045oxnSZ_kgQt-pdN7AxGWOVvwoTf9am6mSkEdv6iw",
            },
        )
        self.parse_config()

    def test_registration_cannot_be_enabled(self) -> None:
        self.config_dict["enable_registration"] = True
        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_user_consent_cannot_be_enabled(self) -> None:
        tmpdir = self.mktemp()
        os.mkdir(tmpdir)
        self.config_dict["user_consent"] = {
            "require_at_registration": True,
            "version": "1",
            "template_dir": tmpdir,
            "server_notice_content": {
                "msgtype": "m.text",
                "body": "foo",
            },
        }
        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_password_config_cannot_be_enabled(self) -> None:
        self.config_dict["password_config"] = {"enabled": True}
        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_oidc_sso_cannot_be_enabled(self) -> None:
        self.config_dict["oidc_providers"] = [
            {
                "idp_id": "microsoft",
                "idp_name": "Microsoft",
                "issuer": "https://login.microsoftonline.com/<tenant id>/v2.0",
                "client_id": "<client id>",
                "client_secret": "<client secret>",
                "scopes": ["openid", "profile"],
                "authorization_endpoint": "https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/authorize",
                "token_endpoint": "https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token",
                "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
            }
        ]

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_cas_sso_cannot_be_enabled(self) -> None:
        self.config_dict["cas_config"] = {
            "enabled": True,
            "server_url": "https://cas-server.com",
            "displayname_attribute": "name",
            "required_attributes": {"userGroup": "staff", "department": "None"},
        }

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_auth_providers_cannot_be_enabled(self) -> None:
        self.config_dict["modules"] = [
            {
                "module": f"{__name__}.{CustomAuthModule.__qualname__}",
                "config": {},
            }
        ]

        # This requires actually setting up an HS, as the module will be run on setup,
        # which should raise as the module tries to register an auth provider
        config = self.parse_config()
        reactor, clock = get_clock()
        with self.assertRaises(ConfigError):
            setup_test_homeserver(
                self.addCleanup, reactor=reactor, clock=clock, config=config
            )

    def test_jwt_auth_cannot_be_enabled(self) -> None:
        self.config_dict["jwt_config"] = {
            "enabled": True,
            "secret": "my-secret-token",
            "algorithm": "HS256",
        }

        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_login_via_existing_session_cannot_be_enabled(self) -> None:
        self.config_dict["login_via_existing_session"] = {"enabled": True}
        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_captcha_cannot_be_enabled(self) -> None:
        self.config_dict.update(
            enable_registration_captcha=True,
            recaptcha_public_key="test",
            recaptcha_private_key="test",
        )
        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_refreshable_tokens_cannot_be_enabled(self) -> None:
        self.config_dict.update(
            refresh_token_lifetime="24h",
            refreshable_access_token_lifetime="10m",
            nonrefreshable_access_token_lifetime="24h",
        )
        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_session_lifetime_cannot_be_set(self) -> None:
        self.config_dict["session_lifetime"] = "24h"
        with self.assertRaises(ConfigError):
            self.parse_config()

    def test_enable_3pid_changes_cannot_be_enabled(self) -> None:
        self.config_dict["enable_3pid_changes"] = True
        with self.assertRaises(ConfigError):
            self.parse_config()
