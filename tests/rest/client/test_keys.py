#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License
import urllib.parse
from http import HTTPStatus
from unittest.mock import patch

from signedjson.key import (
    encode_verify_key_base64,
    generate_signing_key,
    get_verify_key,
)
from signedjson.sign import sign_json

from synapse.api.errors import Codes
from synapse.rest import admin
from synapse.rest.client import keys, login
from synapse.types import JsonDict, Requester, create_requester

from tests import unittest
from tests.http.server._base import make_request_with_cancellation_test
from tests.unittest import override_config
from tests.utils import HAS_AUTHLIB


class KeyQueryTestCase(unittest.HomeserverTestCase):
    servlets = [
        keys.register_servlets,
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
    ]

    def test_rejects_device_id_ice_key_outside_of_list(self) -> None:
        self.register_user("alice", "wonderland")
        alice_token = self.login("alice", "wonderland")
        bob = self.register_user("bob", "uncle")
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/keys/query",
            {
                "device_keys": {
                    bob: "device_id1",
                },
            },
            alice_token,
        )
        self.assertEqual(channel.code, HTTPStatus.BAD_REQUEST, channel.result)
        self.assertEqual(
            channel.json_body["errcode"],
            Codes.BAD_JSON,
            channel.result,
        )

    def test_rejects_device_key_given_as_map_to_bool(self) -> None:
        self.register_user("alice", "wonderland")
        alice_token = self.login("alice", "wonderland")
        bob = self.register_user("bob", "uncle")
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/keys/query",
            {
                "device_keys": {
                    bob: {
                        "device_id1": True,
                    },
                },
            },
            alice_token,
        )

        self.assertEqual(channel.code, HTTPStatus.BAD_REQUEST, channel.result)
        self.assertEqual(
            channel.json_body["errcode"],
            Codes.BAD_JSON,
            channel.result,
        )

    def test_requires_device_key(self) -> None:
        """`device_keys` is required. We should complain if it's missing."""
        self.register_user("alice", "wonderland")
        alice_token = self.login("alice", "wonderland")
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/keys/query",
            {},
            alice_token,
        )
        self.assertEqual(channel.code, HTTPStatus.BAD_REQUEST, channel.result)
        self.assertEqual(
            channel.json_body["errcode"],
            Codes.BAD_JSON,
            channel.result,
        )

    def test_key_query_cancellation(self) -> None:
        """
        Tests that /keys/query is cancellable and does not swallow the
        CancelledError.
        """
        self.register_user("alice", "wonderland")
        alice_token = self.login("alice", "wonderland")

        bob = self.register_user("bob", "uncle")

        channel = make_request_with_cancellation_test(
            "test_key_query_cancellation",
            self.reactor,
            self.site,
            "POST",
            "/_matrix/client/r0/keys/query",
            {
                "device_keys": {
                    # Empty list means we request keys for all bob's devices
                    bob: [],
                },
            },
            token=alice_token,
        )

        self.assertEqual(200, channel.code, msg=channel.result["body"])
        self.assertIn(bob, channel.json_body["device_keys"])

    def make_device_keys(self, user_id: str, device_id: str) -> JsonDict:
        # We only generate a master key to simplify the test.
        master_signing_key = generate_signing_key(device_id)
        master_verify_key = encode_verify_key_base64(get_verify_key(master_signing_key))

        return {
            "master_key": sign_json(
                {
                    "user_id": user_id,
                    "usage": ["master"],
                    "keys": {"ed25519:" + master_verify_key: master_verify_key},
                },
                user_id,
                master_signing_key,
            ),
        }

    def test_device_signing_with_uia(self) -> None:
        """Device signing key upload requires UIA."""
        password = "wonderland"
        device_id = "ABCDEFGHI"
        alice_id = self.register_user("alice", password)
        alice_token = self.login("alice", password, device_id=device_id)

        content = self.make_device_keys(alice_id, device_id)

        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            content,
            alice_token,
        )

        self.assertEqual(channel.code, HTTPStatus.UNAUTHORIZED, channel.result)
        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # add UI auth
        content["auth"] = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": alice_id},
            "password": password,
            "session": session,
        }

        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            content,
            alice_token,
        )

        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)

    @override_config({"ui_auth": {"session_timeout": "15m"}})
    def test_device_signing_with_uia_session_timeout(self) -> None:
        """Device signing key upload requires UIA buy passes with grace period."""
        password = "wonderland"
        device_id = "ABCDEFGHI"
        alice_id = self.register_user("alice", password)
        alice_token = self.login("alice", password, device_id=device_id)

        content = self.make_device_keys(alice_id, device_id)

        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            content,
            alice_token,
        )

        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)

    @override_config(
        {
            "experimental_features": {"msc3967_enabled": True},
            "ui_auth": {"session_timeout": "15s"},
        }
    )
    def test_device_signing_with_msc3967(self) -> None:
        """Device signing key follows MSC3967 behaviour when enabled."""
        password = "wonderland"
        device_id = "ABCDEFGHI"
        alice_id = self.register_user("alice", password)
        alice_token = self.login("alice", password, device_id=device_id)

        keys1 = self.make_device_keys(alice_id, device_id)

        # Initial request should succeed as no existing keys are present.
        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            keys1,
            alice_token,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)

        keys2 = self.make_device_keys(alice_id, device_id)

        # Subsequent request should require UIA as keys already exist even though session_timeout is set.
        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            keys2,
            alice_token,
        )
        self.assertEqual(channel.code, HTTPStatus.UNAUTHORIZED, channel.result)

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # add UI auth
        keys2["auth"] = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": alice_id},
            "password": password,
            "session": session,
        }

        # Request should complete
        channel = self.make_request(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            keys2,
            alice_token,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)


class SigningKeyUploadServletTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        keys.register_servlets,
    ]

    OIDC_ADMIN_TOKEN = "_oidc_admin_token"

    @unittest.skip_unless(HAS_AUTHLIB, "requires authlib")
    @override_config(
        {
            "enable_registration": False,
            "experimental_features": {
                "msc3861": {
                    "enabled": True,
                    "issuer": "https://issuer",
                    "account_management_url": "https://my-account.issuer",
                    "client_id": "id",
                    "client_auth_method": "client_secret_post",
                    "client_secret": "secret",
                    "admin_token": OIDC_ADMIN_TOKEN,
                },
            },
        }
    )
    def test_master_cross_signing_key_replacement_msc3861(self) -> None:
        # Provision a user like MAS would, cribbing from
        # https://github.com/matrix-org/matrix-authentication-service/blob/08d46a79a4adb22819ac9d55e15f8375dfe2c5c7/crates/matrix-synapse/src/lib.rs#L224-L229
        alice = "@alice:test"
        channel = self.make_request(
            "PUT",
            f"/_synapse/admin/v2/users/{urllib.parse.quote(alice)}",
            access_token=self.OIDC_ADMIN_TOKEN,
            content={},
        )
        self.assertEqual(channel.code, HTTPStatus.CREATED, channel.json_body)

        # Provision a device like MAS would, cribbing from
        # https://github.com/matrix-org/matrix-authentication-service/blob/08d46a79a4adb22819ac9d55e15f8375dfe2c5c7/crates/matrix-synapse/src/lib.rs#L260-L262
        alice_device = "alice_device"
        channel = self.make_request(
            "POST",
            f"/_synapse/admin/v2/users/{urllib.parse.quote(alice)}/devices",
            access_token=self.OIDC_ADMIN_TOKEN,
            content={"device_id": alice_device},
        )
        self.assertEqual(channel.code, HTTPStatus.CREATED, channel.json_body)

        # Prepare a mock MAS access token.
        alice_token = "alice_token_1234_oidcwhatyoudidthere"

        async def mocked_get_user_by_access_token(
            token: str, allow_expired: bool = False
        ) -> Requester:
            self.assertEqual(token, alice_token)
            return create_requester(
                user_id=alice,
                device_id=alice_device,
                scope=[],
                is_guest=False,
            )

        patch_get_user_by_access_token = patch.object(
            self.hs.get_auth(),
            "get_user_by_access_token",
            wraps=mocked_get_user_by_access_token,
        )

        # Copied from E2eKeysHandlerTestCase
        master_pubkey = "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
        master_pubkey2 = "fHZ3NPiKxoLQm5OoZbKa99SYxprOjNs4TwJUKP+twCM"
        master_pubkey3 = "85T7JXPFBAySB/jwby4S3lBPTqY3+Zg53nYuGmu1ggY"

        master_key: JsonDict = {
            "user_id": alice,
            "usage": ["master"],
            "keys": {"ed25519:" + master_pubkey: master_pubkey},
        }
        master_key2: JsonDict = {
            "user_id": alice,
            "usage": ["master"],
            "keys": {"ed25519:" + master_pubkey2: master_pubkey2},
        }
        master_key3: JsonDict = {
            "user_id": alice,
            "usage": ["master"],
            "keys": {"ed25519:" + master_pubkey3: master_pubkey3},
        }

        with patch_get_user_by_access_token:
            # Upload an initial cross-signing key.
            channel = self.make_request(
                "POST",
                "/_matrix/client/v3/keys/device_signing/upload",
                access_token=alice_token,
                content={
                    "master_key": master_key,
                },
            )
            self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)

            # Should not be able to upload another master key.
            channel = self.make_request(
                "POST",
                "/_matrix/client/v3/keys/device_signing/upload",
                access_token=alice_token,
                content={
                    "master_key": master_key2,
                },
            )
            self.assertEqual(
                channel.code, HTTPStatus.NOT_IMPLEMENTED, channel.json_body
            )

        # Pretend that MAS did UIA and allowed us to replace the master key.
        channel = self.make_request(
            "POST",
            f"/_synapse/admin/v1/users/{urllib.parse.quote(alice)}/_allow_cross_signing_replacement_without_uia",
            access_token=self.OIDC_ADMIN_TOKEN,
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        with patch_get_user_by_access_token:
            # Should now be able to upload master key2.
            channel = self.make_request(
                "POST",
                "/_matrix/client/v3/keys/device_signing/upload",
                access_token=alice_token,
                content={
                    "master_key": master_key2,
                },
            )
            self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)

            # Even though we're still in the grace period, we shouldn't be able to
            # upload master key 3 immediately after uploading key 2.
            channel = self.make_request(
                "POST",
                "/_matrix/client/v3/keys/device_signing/upload",
                access_token=alice_token,
                content={
                    "master_key": master_key3,
                },
            )
            self.assertEqual(
                channel.code, HTTPStatus.NOT_IMPLEMENTED, channel.json_body
            )

        # Pretend that MAS did UIA and allowed us to replace the master key.
        channel = self.make_request(
            "POST",
            f"/_synapse/admin/v1/users/{urllib.parse.quote(alice)}/_allow_cross_signing_replacement_without_uia",
            access_token=self.OIDC_ADMIN_TOKEN,
        )
        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        timestamp_ms = channel.json_body["updatable_without_uia_before_ms"]

        # Advance to 1 second after the replacement period ends.
        self.reactor.advance(timestamp_ms - self.clock.time_msec() + 1000)

        with patch_get_user_by_access_token:
            # We should not be able to upload master key3 because the replacement has
            # expired.
            channel = self.make_request(
                "POST",
                "/_matrix/client/v3/keys/device_signing/upload",
                access_token=alice_token,
                content={
                    "master_key": master_key3,
                },
            )
            self.assertEqual(
                channel.code, HTTPStatus.NOT_IMPLEMENTED, channel.json_body
            )
