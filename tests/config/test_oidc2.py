from copy import deepcopy
from typing import Any, Dict
from unittest import TestCase

import yaml
from pydantic import ValidationError
from parameterized import parameterized

from synapse.config.oidc2 import (
    OIDCProviderModel,
    ClientAuthMethods,
    LegacyOIDCProviderModel,
)

SAMPLE_CONFIG = yaml.safe_load(
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
token_endpoint: https://appleid.apple.com/dummy_url_here
user_mapping_provider:
  config:
    email_template: "{{ user.email }}"
    localpart_template: "{{ user.email|localpart_from_email }}"
    confirm_localpart: true
"""
)


class PydanticOIDCTestCase(TestCase):
    """Examples to build confidence that pydantic is doing the validation we think
    it's doing"""

    # Each test gets a dummy config it can change as it sees fit
    config: Dict[str, Any]

    def setUp(self) -> None:
        self.config = deepcopy(SAMPLE_CONFIG)

    def test_example_config(self):
        # Check that parsing the sample config doesn't raise an error.
        OIDCProviderModel.parse_obj(self.config)

    def test_idp_id(self) -> None:
        """Example of using a Pydantic constr() field without a default."""
        # Enforce that idp_id is required.
        with self.assertRaises(ValidationError):
            del self.config["idp_id"]
            OIDCProviderModel.parse_obj(self.config)

        # Enforce that idp_id is a string.
        for bad_vlaue in 123, None, ["a"], {"a": "b"}:
            with self.assertRaises(ValidationError) as e:
                self.config["idp_id"] = bad_vlaue
                OIDCProviderModel.parse_obj(self.config)

        # Enforce a length between 1 and 250.
        with self.assertRaises(ValidationError):
            self.config["idp_id"] = ""
            OIDCProviderModel.parse_obj(self.config)
        with self.assertRaises(ValidationError):
            self.config["idp_id"] = "a" * 251
            OIDCProviderModel.parse_obj(self.config)

        # Enforce the regex
        with self.assertRaises(ValidationError):
            self.config["idp_id"] = "$"
            OIDCProviderModel.parse_obj(self.config)

        # What happens with a really long string of prohibited characters?
        with self.assertRaises(ValidationError) as e:
            self.config["idp_id"] = "$" * 500
            OIDCProviderModel.parse_obj(self.config)

    def test_legacy_model(self) -> None:
        # Check that parsing the sample config doesn't raise an error.
        LegacyOIDCProviderModel.parse_obj(self.config)

        # Check we have default values for the attributes which have a legacy fallback
        del self.config["idp_id"]
        del self.config["idp_name"]
        model = LegacyOIDCProviderModel.parse_obj(self.config)
        self.assertEqual(model.idp_id, "oidc")
        self.assertEqual(model.idp_name, "OIDC")

        # Check we still reject bad types
        for bad_value in 123, [], {}, None:
            with self.assertRaises(ValidationError) as e:
                self.config["idp_id"] = bad_value
                self.config["idp_name"] = bad_value
                LegacyOIDCProviderModel.parse_obj(self.config)
            # And while we're at it, check that we spot errors in both fields
            reported_bad_fields = {item["loc"] for item in e.exception.errors()}
            expected_bad_fields = {("idp_id",), ("idp_name",)}
            self.assertEqual(
                reported_bad_fields, expected_bad_fields, e.exception.errors()
            )

    def test_issuer(self) -> None:
        """Example of a StrictStr field without a default."""

        # Empty and nonempty strings should be accepted.
        for good_value in "", "hello", "hello" * 1000, "☃":
            self.config["issuer"] = good_value
            OIDCProviderModel.parse_obj(self.config)

        # Invalid types should be rejected.
        for bad_value in 123, None, ["h", "e", "l", "l", "o"], {"hello": "there"}:
            with self.assertRaises(ValidationError):
                self.config["issuer"] = bad_value
                OIDCProviderModel.parse_obj(self.config)

        # A missing issuer should be rejected.
        with self.assertRaises(ValidationError):
            del self.config["issuer"]
            OIDCProviderModel.parse_obj(self.config)

    def test_idp_brand(self) -> None:
        """Example of an Optional[StrictStr] field."""
        # Empty and nonempty strings should be accepted.
        for good_value in "", "hello", "hello" * 1000, "☃":
            self.config["idp_brand"] = good_value
            OIDCProviderModel.parse_obj(self.config)

        # Invalid types should be rejected.
        for bad_value in 123, ["h", "e", "l", "l", "o"], {"hello": "there"}:
            with self.assertRaises(ValidationError):
                self.config["idp_brand"] = bad_value
                OIDCProviderModel.parse_obj(self.config)

        # A lack of an idp_brand is fine...
        del self.config["idp_brand"]
        model = OIDCProviderModel.parse_obj(self.config)
        self.assertIsNone(model.idp_brand)

        # ... and interpreted the same as an explicit `None`.
        self.config["idp_brand"] = None
        model = OIDCProviderModel.parse_obj(self.config)
        self.assertIsNone(model.idp_brand)

    def test_idp_icon(self) -> None:
        # Test that bad types are rejected, even with our validator in place
        for bad_value in None, {}, [], 123, 45.6:
            with self.assertRaises(ValidationError):
                self.config["idp_icon"] = bad_value
                OIDCProviderModel.parse_obj(self.config)

        # Test that bad strings are rejected by our validator
        for bad_value in "", "notaurl", "https://example.com", "mxc://mxc://mxc://":
            with self.assertRaises(ValidationError):
                self.config["idp_icon"] = bad_value
                OIDCProviderModel.parse_obj(self.config)

    def test_discover(self) -> None:
        """Example of a StrictBool field with a default."""
        # Booleans are permitted.
        for value in True, False:
            self.config["discover"] = value
            model = OIDCProviderModel.parse_obj(self.config)
            self.assertEqual(model.discover, value)

        # Invalid types should be rejected.
        for bad_value in (
            -1.0,
            0,
            1,
            float("nan"),
            "yes",
            "NO",
            "True",
            "true",
            None,
            "None",
            "null",
            ["a"],
            {"a": "b"},
        ):
            self.config["discover"] = bad_value
            with self.assertRaises(ValidationError):
                OIDCProviderModel.parse_obj(self.config)

        # A missing value is okay, because this field has a default.
        del self.config["discover"]
        model = OIDCProviderModel.parse_obj(self.config)
        self.assertIs(model.discover, True)

    def test_client_auth_method(self) -> None:
        """This is an example of using a Pydantic string enum field."""
        # check the allowed values are permitted and deserialise to an enum member
        for method in "client_secret_basic", "client_secret_post", "none":
            self.config["client_auth_method"] = method
            model = OIDCProviderModel.parse_obj(self.config)
            self.assertIs(model.client_auth_method, ClientAuthMethods[method])

        # check the default applies if no auth method is provided.
        del self.config["client_auth_method"]
        model = OIDCProviderModel.parse_obj(self.config)
        self.assertIs(model.client_auth_method, ClientAuthMethods.client_secret_basic)

        # Check invalid types are rejected
        for bad_value in 123, ["client_secret_basic"], {"a": 1}, None:
            with self.assertRaises(ValidationError):
                self.config["client_auth_method"] = bad_value
                OIDCProviderModel.parse_obj(self.config)

        # Check that disallowed strings are rejected
        with self.assertRaises(ValidationError):
            self.config["client_auth_method"] = "No, Luke, _I_ am your father!"
            OIDCProviderModel.parse_obj(self.config)

    def test_scopes(self) -> None:
        """Example of a Tuple[StrictStr] with a default."""
        # Check that the parsed object holds a tuple
        self.config["scopes"] = []
        model = OIDCProviderModel.parse_obj(self.config)
        self.assertEqual(model.scopes, ())

        # Check a variety of list lengths are accepted.
        for good_value in ["aa"], ["hello", "world"], ["a"] * 4, [""] * 20:
            self.config["scopes"] = good_value
            model = OIDCProviderModel.parse_obj(self.config)
            self.assertEqual(model.scopes, tuple(good_value))

        # Check invalid types are rejected.
        for bad_value in (
            "",
            "abc",
            123,
            {},
            {"a": 1},
            None,
            [None],
            [["a"]],
            [{}],
            [456],
        ):
            with self.assertRaises(ValidationError):
                self.config["scopes"] = bad_value
                OIDCProviderModel.parse_obj(self.config)

        # Check that "scopes" may be omitted.
        del self.config["scopes"]
        model = OIDCProviderModel.parse_obj(self.config)
        self.assertEqual(model.scopes, ("openid",))

    @parameterized.expand(["authorization_endpoint", "token_endpoint"])
    def test_endpoints_required_when_discovery_disabled(self, key: str) -> None:
        # Test that this field is required if discovery is disabled
        self.config["discover"] = False
        with self.assertRaises(ValidationError):
            self.config[key] = None
            OIDCProviderModel.parse_obj(self.config)
        with self.assertRaises(ValidationError):
            del self.config[key]
            OIDCProviderModel.parse_obj(self.config)
        # We don't validate that the endpoint is a sensible URL; anything str will do
        self.config[key] = "blahblah"
        OIDCProviderModel.parse_obj(self.config)

        def check_all_cases_pass():
            self.config[key] = None
            OIDCProviderModel.parse_obj(self.config)

            del self.config[key]
            OIDCProviderModel.parse_obj(self.config)

            self.config[key] = "blahblah"
            OIDCProviderModel.parse_obj(self.config)

        # With discovery enabled, all three cases are accepted.
        self.config["discover"] = True
        check_all_cases_pass()

        # If not specified, discovery is also on by default.
        del self.config["discover"]
        check_all_cases_pass()
