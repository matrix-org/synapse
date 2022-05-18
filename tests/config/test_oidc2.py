from copy import deepcopy
from typing import Any, Mapping, Dict

import yaml
from pydantic import ValidationError

from synapse.config.oidc2 import OIDCProviderModel
from tests.unittest import TestCase


SAMPLE_CONFIG: Mapping[str, Any] = yaml.safe_load(
    """
idp_id: apple
idp_name: Apple
idp_icon: "mxc://matrix.org/blahblahblah"
idp_brand: "apple"
issuer: "https://appleid.apple.com"
client_id: "org.matrix.synapse.sso.service"
client_secret_jwt_key:
  key: DUMMY_PRIVATE_KEY
  jwt_header:
    alg: ES256
    kid: potato123
  jwt_payload:
    iss: issuer456
client_auth_method: "client_secret_post"
scopes: ["name", "email", "openid"]
authorization_endpoint: https://appleid.apple.com/auth/authorize?response_mode=form_post
user_mapping_provider:
  config:
    email_template: "{{ user.email }}"
    localpart_template: "{{ user.email|localpart_from_email }}"
    confirm_localpart: true
"""
)


class PydanticOIDCTestCase(TestCase):
    # Each test gets a dummy config it can change as it sees fit
    config: Dict[str, Any]

    def setUp(self) -> None:
        self.config = deepcopy(SAMPLE_CONFIG)

    def test_idp_id(self) -> None:
        """Demonstrate that Pydantic validates idp_id correctly."""
        # OIDCProviderModel.parse_obj(self.config)
        #
        # # Enforce that idp_id is required.
        # with self.assertRaises(ValidationError):
        #     del self.config["idp_id"]
        #     OIDCProviderModel.parse_obj(self.config)
        #
        # # Enforce that idp_id is a string.
        # with self.assertRaises(ValidationError):
        #     self.config["idp_id"] = 123
        #     OIDCProviderModel.parse_obj(self.config)
        # with self.assertRaises(ValidationError):
        #     self.config["idp_id"] = None
        #     OIDCProviderModel.parse_obj(self.config)

        # Enforce a length between 1 and 250.
        with self.assertRaises(ValidationError):
            self.config["idp_id"] = ""
            OIDCProviderModel.parse_obj(self.config)
        with self.assertRaises(ValidationError):
            self.config["idp_id"] = "a" * 251
            OIDCProviderModel.parse_obj(self.config)

        # Enforce the character set
        with self.assertRaises(ValidationError):
            self.config["idp_id"] = "$"
            OIDCProviderModel.parse_obj(self.config)
