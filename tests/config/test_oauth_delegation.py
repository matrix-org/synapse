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

from typing import Any, Dict
from unittest.mock import Mock

from synapse.config import ConfigError
from synapse.module_api import ModuleApi
from synapse.types import JsonDict

from tests.server import get_clock
from tests.unittest import HomeserverTestCase, override_config, skip_unless

try:
    import authlib  # noqa: F401

    HAS_AUTHLIB = True
except ImportError:
    HAS_AUTHLIB = False


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
class MSC3861OAuthDelegation(HomeserverTestCase):
    """Test that the Homeserver fails to initialize if the config is invalid."""

    def setUp(self) -> None:
        self.reactor, self.clock = get_clock()
        self._hs_args = {"clock": self.clock, "reactor": self.reactor}

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["public_baseurl"] = BASE_URL
        if "experimental_features" not in config:
            config["experimental_features"] = {}
        config["experimental_features"]["msc3861"] = {
            "enabled": True,
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_auth_method": "client_secret_post",
            "client_secret": CLIENT_SECRET,
        }
        return config

    def test_registration_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "password_config": {
                "enabled": True,
            },
        }
    )
    def test_password_config_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "oidc_providers": [
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
            ],
        }
    )
    def test_oidc_sso_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "cas_config": {
                "enabled": True,
                "server_url": "https://cas-server.com",
                "displayname_attribute": "name",
                "required_attributes": {"userGroup": "staff", "department": "None"},
            },
        }
    )
    def test_cas_sso_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "modules": [
                {
                    "module": f"{__name__}.{CustomAuthModule.__qualname__}",
                    "config": {},
                }
            ],
        }
    )
    def test_auth_providers_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "jwt_config": {
                "enabled": True,
                "secret": "my-secret-token",
                "algorithm": "HS256",
            },
        }
    )
    def test_jwt_auth_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "experimental_features": {
                "msc3882_enabled": True,
            },
        }
    )
    def test_msc3882_auth_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "recaptcha_public_key": "test",
            "recaptcha_private_key": "test",
            "enable_registration_captcha": True,
        }
    )
    def test_captcha_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "refresh_token_lifetime": "24h",
            "refreshable_access_token_lifetime": "10m",
            "nonrefreshable_access_token_lifetime": "24h",
        }
    )
    def test_refreshable_tokens_cannot_be_enabled(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()

    @override_config(
        {
            "enable_registration": False,
            "session_lifetime": "24h",
        }
    )
    def test_session_lifetime_cannot_be_set(self) -> None:
        with self.assertRaises(ConfigError):
            self.setup_test_homeserver()
