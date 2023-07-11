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

from http import HTTPStatus

from signedjson.key import (
    encode_verify_key_base64,
    generate_signing_key,
    get_verify_key,
)
from signedjson.sign import sign_json

from synapse.api.errors import Codes
from synapse.rest import admin
from synapse.rest.client import keys, login
from synapse.types import JsonDict

from tests import unittest
from tests.http.server._base import make_request_with_cancellation_test
from tests.unittest import override_config


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
