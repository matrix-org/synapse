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
import urllib.parse
from io import BytesIO

from mock import Mock

import signedjson.key
from nacl.signing import SigningKey
from signedjson.sign import sign_json

from twisted.web.resource import NoResource

from synapse.http.site import SynapseRequest
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.util.httpresourcetree import create_resource_tree

from tests import unittest
from tests.server import FakeChannel, wait_until_result


class RemoteKeyResourceTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        self.http_client = Mock()
        return self.setup_test_homeserver(http_client=self.http_client)

    def create_test_json_resource(self):
        return create_resource_tree(
            {"/_matrix/key/v2": KeyApiV2Resource(self.hs)}, root_resource=NoResource()
        )

    def expect_outgoing_key_request(
        self, server_name: str, signing_key: SigningKey
    ) -> None:
        """
        Tell the mock http client to expect an outgoing GET request for the given key
        """

        def get_json(destination, path, ignore_backoff=False, **kwargs):
            self.assertTrue(ignore_backoff)
            self.assertEqual(destination, server_name)
            key_id = "%s:%s" % (signing_key.alg, signing_key.version)
            self.assertEqual(
                path, "/_matrix/key/v2/server/%s" % (urllib.parse.quote(key_id),)
            )

            response = {
                "server_name": server_name,
                "old_verify_keys": {},
                "valid_until_ts": 200 * 1000,
                "verify_keys": {
                    key_id: {
                        "key": signedjson.key.encode_verify_key_base64(
                            signing_key.verify_key
                        )
                    }
                },
            }
            sign_json(response, server_name, signing_key)
            return response

        self.http_client.get_json.side_effect = get_json

    def make_notary_request(self, server_name: str, key_id: str) -> dict:
        """Send a GET request to the test server requesting the given key.

        Checks that the response is a 200 and returns the decoded json body.
        """
        channel = FakeChannel(self.site, self.reactor)
        req = SynapseRequest(channel)
        req.content = BytesIO(b"")
        req.requestReceived(
            b"GET",
            b"/_matrix/key/v2/query/%s/%s"
            % (server_name.encode("utf-8"), key_id.encode("utf-8")),
            b"1.1",
        )
        wait_until_result(self.reactor, req)
        self.assertEqual(channel.code, 200)
        resp = channel.json_body
        return resp

    def test_get_key(self):
        """Fetch a remote key"""
        SERVER_NAME = "remote.server"
        testkey = signedjson.key.generate_signing_key("ver1")
        self.expect_outgoing_key_request(SERVER_NAME, testkey)

        resp = self.make_notary_request(SERVER_NAME, "ed25519:ver1")
        keys = resp["server_keys"]
        self.assertEqual(len(keys), 1)

        self.assertIn("ed25519:ver1", keys[0]["verify_keys"])
        self.assertEqual(len(keys[0]["verify_keys"]), 1)

        # it should be signed by both the origin server and the notary
        self.assertIn(SERVER_NAME, keys[0]["signatures"])
        self.assertIn(self.hs.hostname, keys[0]["signatures"])

    def test_get_own_key(self):
        """Fetch our own key"""
        testkey = signedjson.key.generate_signing_key("ver1")
        self.expect_outgoing_key_request(self.hs.hostname, testkey)

        resp = self.make_notary_request(self.hs.hostname, "ed25519:ver1")
        keys = resp["server_keys"]
        self.assertEqual(len(keys), 1)

        # it should be signed by both itself, and the notary signing key
        sigs = keys[0]["signatures"]
        self.assertEqual(len(sigs), 1)
        self.assertIn(self.hs.hostname, sigs)
        oursigs = sigs[self.hs.hostname]
        self.assertEqual(len(oursigs), 2)

        # and both keys should be present in the verify_keys section
        self.assertIn("ed25519:ver1", keys[0]["verify_keys"])
        self.assertIn("ed25519:a_lPym", keys[0]["verify_keys"])
