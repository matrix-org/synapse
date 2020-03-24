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
from io import BytesIO, StringIO

from mock import Mock

import signedjson.key
from canonicaljson import encode_canonical_json
from nacl.signing import SigningKey
from signedjson.sign import sign_json

from twisted.web.resource import NoResource

from synapse.crypto.keyring import PerspectivesKeyFetcher
from synapse.http.site import SynapseRequest
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.storage.keys import FetchKeyResult
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.stringutils import random_string

from tests import unittest
from tests.server import FakeChannel, wait_until_result
from tests.utils import default_config


class BaseRemoteKeyResourceTestCase(unittest.HomeserverTestCase):
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


class RemoteKeyResourceTestCase(BaseRemoteKeyResourceTestCase):
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

        # the requested key should be present in the verify_keys section
        self.assertIn("ed25519:ver1", keys[0]["verify_keys"])


class EndToEndPerspectivesTests(BaseRemoteKeyResourceTestCase):
    """End-to-end tests of the perspectives fetch case

    The idea here is to actually wire up a PerspectivesKeyFetcher to the notary
    endpoint, to check that the two implementations are compatible.
    """

    def default_config(self):
        config = super().default_config()

        # replace the signing key with our own
        self.hs_signing_key = signedjson.key.generate_signing_key("kssk")
        strm = StringIO()
        signedjson.key.write_signing_keys(strm, [self.hs_signing_key])
        config["signing_key"] = strm.getvalue()

        return config

    def prepare(self, reactor, clock, homeserver):
        # make a second homeserver, configured to use the first one as a key notary
        self.http_client2 = Mock()
        config = default_config(name="keyclient")
        config["trusted_key_servers"] = [
            {
                "server_name": self.hs.hostname,
                "verify_keys": {
                    "ed25519:%s"
                    % (
                        self.hs_signing_key.version,
                    ): signedjson.key.encode_verify_key_base64(
                        self.hs_signing_key.verify_key
                    )
                },
            }
        ]
        self.hs2 = self.setup_test_homeserver(
            http_client=self.http_client2, config=config
        )

        # wire up outbound POST /key/v2/query requests from hs2 so that they
        # will be forwarded to hs1
        def post_json(destination, path, data):
            self.assertEqual(destination, self.hs.hostname)
            self.assertEqual(
                path, "/_matrix/key/v2/query",
            )

            channel = FakeChannel(self.site, self.reactor)
            req = SynapseRequest(channel)
            req.content = BytesIO(encode_canonical_json(data))

            req.requestReceived(
                b"POST", path.encode("utf-8"), b"1.1",
            )
            wait_until_result(self.reactor, req)
            self.assertEqual(channel.code, 200)
            resp = channel.json_body
            return resp

        self.http_client2.post_json.side_effect = post_json

    def test_get_key(self):
        """Fetch a key belonging to a random server"""
        # make up a key to be fetched.
        testkey = signedjson.key.generate_signing_key("abc")

        # we expect hs1 to make a regular key request to the target server
        self.expect_outgoing_key_request("targetserver", testkey)
        keyid = "ed25519:%s" % (testkey.version,)

        fetcher = PerspectivesKeyFetcher(self.hs2)
        d = fetcher.get_keys({"targetserver": {keyid: 1000}})
        res = self.get_success(d)
        self.assertIn("targetserver", res)
        keyres = res["targetserver"][keyid]
        assert isinstance(keyres, FetchKeyResult)
        self.assertEqual(
            signedjson.key.encode_verify_key_base64(keyres.verify_key),
            signedjson.key.encode_verify_key_base64(testkey.verify_key),
        )

    def test_get_notary_key(self):
        """Fetch a key belonging to the notary server"""
        # make up a key to be fetched. We randomise the keyid to try to get it to
        # appear before the key server signing key sometimes (otherwise we bail out
        # before fetching its signature)
        testkey = signedjson.key.generate_signing_key(random_string(5))

        # we expect hs1 to make a regular key request to itself
        self.expect_outgoing_key_request(self.hs.hostname, testkey)
        keyid = "ed25519:%s" % (testkey.version,)

        fetcher = PerspectivesKeyFetcher(self.hs2)
        d = fetcher.get_keys({self.hs.hostname: {keyid: 1000}})
        res = self.get_success(d)
        self.assertIn(self.hs.hostname, res)
        keyres = res[self.hs.hostname][keyid]
        assert isinstance(keyres, FetchKeyResult)
        self.assertEqual(
            signedjson.key.encode_verify_key_base64(keyres.verify_key),
            signedjson.key.encode_verify_key_base64(testkey.verify_key),
        )

    def test_get_notary_keyserver_key(self):
        """Fetch the notary's keyserver key"""
        # we expect hs1 to make a regular key request to itself
        self.expect_outgoing_key_request(self.hs.hostname, self.hs_signing_key)
        keyid = "ed25519:%s" % (self.hs_signing_key.version,)

        fetcher = PerspectivesKeyFetcher(self.hs2)
        d = fetcher.get_keys({self.hs.hostname: {keyid: 1000}})
        res = self.get_success(d)
        self.assertIn(self.hs.hostname, res)
        keyres = res[self.hs.hostname][keyid]
        assert isinstance(keyres, FetchKeyResult)
        self.assertEqual(
            signedjson.key.encode_verify_key_base64(keyres.verify_key),
            signedjson.key.encode_verify_key_base64(self.hs_signing_key.verify_key),
        )
