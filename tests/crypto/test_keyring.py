# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
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
import time
from unittest.mock import Mock

import attr
import canonicaljson
import signedjson.key
import signedjson.sign
from nacl.signing import SigningKey
from signedjson.key import encode_verify_key_base64, get_verify_key

from twisted.internet import defer
from twisted.internet.defer import Deferred, ensureDeferred

from synapse.api.errors import SynapseError
from synapse.crypto import keyring
from synapse.crypto.keyring import (
    PerspectivesKeyFetcher,
    ServerKeyFetcher,
    StoreKeyFetcher,
)
from synapse.logging.context import (
    LoggingContext,
    current_context,
    make_deferred_yieldable,
)
from synapse.storage.keys import FetchKeyResult

from tests import unittest
from tests.test_utils import make_awaitable
from tests.unittest import logcontext_clean


class MockPerspectiveServer:
    def __init__(self):
        self.server_name = "mock_server"
        self.key = signedjson.key.generate_signing_key(0)

    def get_verify_keys(self):
        vk = signedjson.key.get_verify_key(self.key)
        return {"%s:%s" % (vk.alg, vk.version): encode_verify_key_base64(vk)}

    def get_signed_key(self, server_name, verify_key):
        key_id = "%s:%s" % (verify_key.alg, verify_key.version)
        res = {
            "server_name": server_name,
            "old_verify_keys": {},
            "valid_until_ts": time.time() * 1000 + 3600,
            "verify_keys": {key_id: {"key": encode_verify_key_base64(verify_key)}},
        }
        self.sign_response(res)
        return res

    def sign_response(self, res):
        signedjson.sign.sign_json(res, self.server_name, self.key)


@attr.s(slots=True)
class FakeRequest:
    id = attr.ib()


@logcontext_clean
class KeyringTestCase(unittest.HomeserverTestCase):
    def check_context(self, val, expected):
        self.assertEquals(getattr(current_context(), "request", None), expected)
        return val

    def test_verify_json_objects_for_server_awaits_previous_requests(self):
        mock_fetcher = Mock()
        mock_fetcher.get_keys = Mock()
        kr = keyring.Keyring(self.hs, key_fetchers=(mock_fetcher,))

        # a signed object that we are going to try to validate
        key1 = signedjson.key.generate_signing_key(1)
        json1 = {}
        signedjson.sign.sign_json(json1, "server10", key1)

        # start off a first set of lookups. We make the mock fetcher block until this
        # deferred completes.
        first_lookup_deferred = Deferred()

        async def first_lookup_fetch(keys_to_fetch):
            self.assertEquals(current_context().request.id, "context_11")
            self.assertEqual(keys_to_fetch, {"server10": {get_key_id(key1): 0}})

            await make_deferred_yieldable(first_lookup_deferred)
            return {
                "server10": {
                    get_key_id(key1): FetchKeyResult(get_verify_key(key1), 100)
                }
            }

        mock_fetcher.get_keys.side_effect = first_lookup_fetch

        async def first_lookup():
            with LoggingContext("context_11", request=FakeRequest("context_11")):
                res_deferreds = kr.verify_json_objects_for_server(
                    [("server10", json1, 0, "test10"), ("server11", {}, 0, "test11")]
                )

                # the unsigned json should be rejected pretty quickly
                self.assertTrue(res_deferreds[1].called)
                try:
                    await res_deferreds[1]
                    self.assertFalse("unsigned json didn't cause a failure")
                except SynapseError:
                    pass

                self.assertFalse(res_deferreds[0].called)
                res_deferreds[0].addBoth(self.check_context, None)

                await make_deferred_yieldable(res_deferreds[0])

        d0 = ensureDeferred(first_lookup())

        mock_fetcher.get_keys.assert_called_once()

        # a second request for a server with outstanding requests
        # should block rather than start a second call

        async def second_lookup_fetch(keys_to_fetch):
            self.assertEquals(current_context().request.id, "context_12")
            return {
                "server10": {
                    get_key_id(key1): FetchKeyResult(get_verify_key(key1), 100)
                }
            }

        mock_fetcher.get_keys.reset_mock()
        mock_fetcher.get_keys.side_effect = second_lookup_fetch
        second_lookup_state = [0]

        async def second_lookup():
            with LoggingContext("context_12", request=FakeRequest("context_12")):
                res_deferreds_2 = kr.verify_json_objects_for_server(
                    [("server10", json1, 0, "test")]
                )
                res_deferreds_2[0].addBoth(self.check_context, None)
                second_lookup_state[0] = 1
                await make_deferred_yieldable(res_deferreds_2[0])
                second_lookup_state[0] = 2

        d2 = ensureDeferred(second_lookup())

        self.pump()
        # the second request should be pending, but the fetcher should not yet have been
        # called
        self.assertEqual(second_lookup_state[0], 1)
        mock_fetcher.get_keys.assert_not_called()

        # complete the first request
        first_lookup_deferred.callback(None)

        # and now both verifications should succeed.
        self.get_success(d0)
        self.get_success(d2)

    def test_verify_json_for_server(self):
        kr = keyring.Keyring(self.hs)

        key1 = signedjson.key.generate_signing_key(1)
        r = self.hs.get_datastore().store_server_verify_keys(
            "server9",
            time.time() * 1000,
            [("server9", get_key_id(key1), FetchKeyResult(get_verify_key(key1), 1000))],
        )
        self.get_success(r)

        json1 = {}
        signedjson.sign.sign_json(json1, "server9", key1)

        # should fail immediately on an unsigned object
        d = _verify_json_for_server(kr, "server9", {}, 0, "test unsigned")
        self.get_failure(d, SynapseError)

        # should succeed on a signed object
        d = _verify_json_for_server(kr, "server9", json1, 500, "test signed")
        # self.assertFalse(d.called)
        self.get_success(d)

    def test_verify_json_for_server_with_null_valid_until_ms(self):
        """Tests that we correctly handle key requests for keys we've stored
        with a null `ts_valid_until_ms`
        """
        mock_fetcher = Mock()
        mock_fetcher.get_keys = Mock(return_value=make_awaitable({}))

        kr = keyring.Keyring(
            self.hs, key_fetchers=(StoreKeyFetcher(self.hs), mock_fetcher)
        )

        key1 = signedjson.key.generate_signing_key(1)
        r = self.hs.get_datastore().store_server_verify_keys(
            "server9",
            time.time() * 1000,
            [("server9", get_key_id(key1), FetchKeyResult(get_verify_key(key1), None))],
        )
        self.get_success(r)

        json1 = {}
        signedjson.sign.sign_json(json1, "server9", key1)

        # should fail immediately on an unsigned object
        d = _verify_json_for_server(kr, "server9", {}, 0, "test unsigned")
        self.get_failure(d, SynapseError)

        # should fail on a signed object with a non-zero minimum_valid_until_ms,
        # as it tries to refetch the keys and fails.
        d = _verify_json_for_server(
            kr, "server9", json1, 500, "test signed non-zero min"
        )
        self.get_failure(d, SynapseError)

        # We expect the keyring tried to refetch the key once.
        mock_fetcher.get_keys.assert_called_once_with(
            {"server9": {get_key_id(key1): 500}}
        )

        # should succeed on a signed object with a 0 minimum_valid_until_ms
        d = _verify_json_for_server(
            kr, "server9", json1, 0, "test signed with zero min"
        )
        self.get_success(d)

    def test_verify_json_dedupes_key_requests(self):
        """Two requests for the same key should be deduped."""
        key1 = signedjson.key.generate_signing_key(1)

        async def get_keys(keys_to_fetch):
            # there should only be one request object (with the max validity)
            self.assertEqual(keys_to_fetch, {"server1": {get_key_id(key1): 1500}})

            return {
                "server1": {
                    get_key_id(key1): FetchKeyResult(get_verify_key(key1), 1200)
                }
            }

        mock_fetcher = Mock()
        mock_fetcher.get_keys = Mock(side_effect=get_keys)
        kr = keyring.Keyring(self.hs, key_fetchers=(mock_fetcher,))

        json1 = {}
        signedjson.sign.sign_json(json1, "server1", key1)

        # the first request should succeed; the second should fail because the key
        # has expired
        results = kr.verify_json_objects_for_server(
            [("server1", json1, 500, "test1"), ("server1", json1, 1500, "test2")]
        )
        self.assertEqual(len(results), 2)
        self.get_success(results[0])
        e = self.get_failure(results[1], SynapseError).value
        self.assertEqual(e.errcode, "M_UNAUTHORIZED")
        self.assertEqual(e.code, 401)

        # there should have been a single call to the fetcher
        mock_fetcher.get_keys.assert_called_once()

    def test_verify_json_falls_back_to_other_fetchers(self):
        """If the first fetcher cannot provide a recent enough key, we fall back"""
        key1 = signedjson.key.generate_signing_key(1)

        async def get_keys1(keys_to_fetch):
            self.assertEqual(keys_to_fetch, {"server1": {get_key_id(key1): 1500}})
            return {
                "server1": {get_key_id(key1): FetchKeyResult(get_verify_key(key1), 800)}
            }

        async def get_keys2(keys_to_fetch):
            self.assertEqual(keys_to_fetch, {"server1": {get_key_id(key1): 1500}})
            return {
                "server1": {
                    get_key_id(key1): FetchKeyResult(get_verify_key(key1), 1200)
                }
            }

        mock_fetcher1 = Mock()
        mock_fetcher1.get_keys = Mock(side_effect=get_keys1)
        mock_fetcher2 = Mock()
        mock_fetcher2.get_keys = Mock(side_effect=get_keys2)
        kr = keyring.Keyring(self.hs, key_fetchers=(mock_fetcher1, mock_fetcher2))

        json1 = {}
        signedjson.sign.sign_json(json1, "server1", key1)

        results = kr.verify_json_objects_for_server(
            [("server1", json1, 1200, "test1"), ("server1", json1, 1500, "test2")]
        )
        self.assertEqual(len(results), 2)
        self.get_success(results[0])
        e = self.get_failure(results[1], SynapseError).value
        self.assertEqual(e.errcode, "M_UNAUTHORIZED")
        self.assertEqual(e.code, 401)

        # there should have been a single call to each fetcher
        mock_fetcher1.get_keys.assert_called_once()
        mock_fetcher2.get_keys.assert_called_once()


@logcontext_clean
class ServerKeyFetcherTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        self.http_client = Mock()
        hs = self.setup_test_homeserver(federation_http_client=self.http_client)
        return hs

    def test_get_keys_from_server(self):
        # arbitrarily advance the clock a bit
        self.reactor.advance(100)

        SERVER_NAME = "server2"
        fetcher = ServerKeyFetcher(self.hs)
        testkey = signedjson.key.generate_signing_key("ver1")
        testverifykey = signedjson.key.get_verify_key(testkey)
        testverifykey_id = "ed25519:ver1"
        VALID_UNTIL_TS = 200 * 1000

        # valid response
        response = {
            "server_name": SERVER_NAME,
            "old_verify_keys": {},
            "valid_until_ts": VALID_UNTIL_TS,
            "verify_keys": {
                testverifykey_id: {
                    "key": signedjson.key.encode_verify_key_base64(testverifykey)
                }
            },
        }
        signedjson.sign.sign_json(response, SERVER_NAME, testkey)

        async def get_json(destination, path, **kwargs):
            self.assertEqual(destination, SERVER_NAME)
            self.assertEqual(path, "/_matrix/key/v2/server/key1")
            return response

        self.http_client.get_json.side_effect = get_json

        keys_to_fetch = {SERVER_NAME: {"key1": 0}}
        keys = self.get_success(fetcher.get_keys(keys_to_fetch))
        k = keys[SERVER_NAME][testverifykey_id]
        self.assertEqual(k.valid_until_ts, VALID_UNTIL_TS)
        self.assertEqual(k.verify_key, testverifykey)
        self.assertEqual(k.verify_key.alg, "ed25519")
        self.assertEqual(k.verify_key.version, "ver1")

        # check that the perspectives store is correctly updated
        lookup_triplet = (SERVER_NAME, testverifykey_id, None)
        key_json = self.get_success(
            self.hs.get_datastore().get_server_keys_json([lookup_triplet])
        )
        res = key_json[lookup_triplet]
        self.assertEqual(len(res), 1)
        res = res[0]
        self.assertEqual(res["key_id"], testverifykey_id)
        self.assertEqual(res["from_server"], SERVER_NAME)
        self.assertEqual(res["ts_added_ms"], self.reactor.seconds() * 1000)
        self.assertEqual(res["ts_valid_until_ms"], VALID_UNTIL_TS)

        # we expect it to be encoded as canonical json *before* it hits the db
        self.assertEqual(
            bytes(res["key_json"]), canonicaljson.encode_canonical_json(response)
        )

        # change the server name: the result should be ignored
        response["server_name"] = "OTHER_SERVER"

        keys = self.get_success(fetcher.get_keys(keys_to_fetch))
        self.assertEqual(keys, {})


class PerspectivesKeyFetcherTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        self.mock_perspective_server = MockPerspectiveServer()
        self.http_client = Mock()

        config = self.default_config()
        config["trusted_key_servers"] = [
            {
                "server_name": self.mock_perspective_server.server_name,
                "verify_keys": self.mock_perspective_server.get_verify_keys(),
            }
        ]

        return self.setup_test_homeserver(
            federation_http_client=self.http_client, config=config
        )

    def build_perspectives_response(
        self,
        server_name: str,
        signing_key: SigningKey,
        valid_until_ts: int,
    ) -> dict:
        """
        Build a valid perspectives server response to a request for the given key
        """
        verify_key = signedjson.key.get_verify_key(signing_key)
        verifykey_id = "%s:%s" % (verify_key.alg, verify_key.version)

        response = {
            "server_name": server_name,
            "old_verify_keys": {},
            "valid_until_ts": valid_until_ts,
            "verify_keys": {
                verifykey_id: {
                    "key": signedjson.key.encode_verify_key_base64(verify_key)
                }
            },
        }
        # the response must be signed by both the origin server and the perspectives
        # server.
        signedjson.sign.sign_json(response, server_name, signing_key)
        self.mock_perspective_server.sign_response(response)
        return response

    def expect_outgoing_key_query(
        self, expected_server_name: str, expected_key_id: str, response: dict
    ) -> None:
        """
        Tell the mock http client to expect a perspectives-server key query
        """

        async def post_json(destination, path, data, **kwargs):
            self.assertEqual(destination, self.mock_perspective_server.server_name)
            self.assertEqual(path, "/_matrix/key/v2/query")

            # check that the request is for the expected key
            q = data["server_keys"]
            self.assertEqual(list(q[expected_server_name].keys()), [expected_key_id])
            return {"server_keys": [response]}

        self.http_client.post_json.side_effect = post_json

    def test_get_keys_from_perspectives(self):
        # arbitrarily advance the clock a bit
        self.reactor.advance(100)

        fetcher = PerspectivesKeyFetcher(self.hs)

        SERVER_NAME = "server2"
        testkey = signedjson.key.generate_signing_key("ver1")
        testverifykey = signedjson.key.get_verify_key(testkey)
        testverifykey_id = "ed25519:ver1"
        VALID_UNTIL_TS = 200 * 1000

        response = self.build_perspectives_response(
            SERVER_NAME,
            testkey,
            VALID_UNTIL_TS,
        )

        self.expect_outgoing_key_query(SERVER_NAME, "key1", response)

        keys_to_fetch = {SERVER_NAME: {"key1": 0}}
        keys = self.get_success(fetcher.get_keys(keys_to_fetch))
        self.assertIn(SERVER_NAME, keys)
        k = keys[SERVER_NAME][testverifykey_id]
        self.assertEqual(k.valid_until_ts, VALID_UNTIL_TS)
        self.assertEqual(k.verify_key, testverifykey)
        self.assertEqual(k.verify_key.alg, "ed25519")
        self.assertEqual(k.verify_key.version, "ver1")

        # check that the perspectives store is correctly updated
        lookup_triplet = (SERVER_NAME, testverifykey_id, None)
        key_json = self.get_success(
            self.hs.get_datastore().get_server_keys_json([lookup_triplet])
        )
        res = key_json[lookup_triplet]
        self.assertEqual(len(res), 1)
        res = res[0]
        self.assertEqual(res["key_id"], testverifykey_id)
        self.assertEqual(res["from_server"], self.mock_perspective_server.server_name)
        self.assertEqual(res["ts_added_ms"], self.reactor.seconds() * 1000)
        self.assertEqual(res["ts_valid_until_ms"], VALID_UNTIL_TS)

        self.assertEqual(
            bytes(res["key_json"]), canonicaljson.encode_canonical_json(response)
        )

    def test_get_perspectives_own_key(self):
        """Check that we can get the perspectives server's own keys

        This is slightly complicated by the fact that the perspectives server may
        use different keys for signing notary responses.
        """

        # arbitrarily advance the clock a bit
        self.reactor.advance(100)

        fetcher = PerspectivesKeyFetcher(self.hs)

        SERVER_NAME = self.mock_perspective_server.server_name
        testkey = signedjson.key.generate_signing_key("ver1")
        testverifykey = signedjson.key.get_verify_key(testkey)
        testverifykey_id = "ed25519:ver1"
        VALID_UNTIL_TS = 200 * 1000

        response = self.build_perspectives_response(
            SERVER_NAME, testkey, VALID_UNTIL_TS
        )

        self.expect_outgoing_key_query(SERVER_NAME, "key1", response)

        keys_to_fetch = {SERVER_NAME: {"key1": 0}}
        keys = self.get_success(fetcher.get_keys(keys_to_fetch))
        self.assertIn(SERVER_NAME, keys)
        k = keys[SERVER_NAME][testverifykey_id]
        self.assertEqual(k.valid_until_ts, VALID_UNTIL_TS)
        self.assertEqual(k.verify_key, testverifykey)
        self.assertEqual(k.verify_key.alg, "ed25519")
        self.assertEqual(k.verify_key.version, "ver1")

        # check that the perspectives store is correctly updated
        lookup_triplet = (SERVER_NAME, testverifykey_id, None)
        key_json = self.get_success(
            self.hs.get_datastore().get_server_keys_json([lookup_triplet])
        )
        res = key_json[lookup_triplet]
        self.assertEqual(len(res), 1)
        res = res[0]
        self.assertEqual(res["key_id"], testverifykey_id)
        self.assertEqual(res["from_server"], self.mock_perspective_server.server_name)
        self.assertEqual(res["ts_added_ms"], self.reactor.seconds() * 1000)
        self.assertEqual(res["ts_valid_until_ms"], VALID_UNTIL_TS)

        self.assertEqual(
            bytes(res["key_json"]), canonicaljson.encode_canonical_json(response)
        )

    def test_invalid_perspectives_responses(self):
        """Check that invalid responses from the perspectives server are rejected"""
        # arbitrarily advance the clock a bit
        self.reactor.advance(100)

        SERVER_NAME = "server2"
        testkey = signedjson.key.generate_signing_key("ver1")
        testverifykey = signedjson.key.get_verify_key(testkey)
        testverifykey_id = "ed25519:ver1"
        VALID_UNTIL_TS = 200 * 1000

        def build_response():
            return self.build_perspectives_response(
                SERVER_NAME, testkey, VALID_UNTIL_TS
            )

        def get_key_from_perspectives(response):
            fetcher = PerspectivesKeyFetcher(self.hs)
            keys_to_fetch = {SERVER_NAME: {"key1": 0}}
            self.expect_outgoing_key_query(SERVER_NAME, "key1", response)
            return self.get_success(fetcher.get_keys(keys_to_fetch))

        # start with a valid response so we can check we are testing the right thing
        response = build_response()
        keys = get_key_from_perspectives(response)
        k = keys[SERVER_NAME][testverifykey_id]
        self.assertEqual(k.verify_key, testverifykey)

        # remove the perspectives server's signature
        response = build_response()
        del response["signatures"][self.mock_perspective_server.server_name]
        keys = get_key_from_perspectives(response)
        self.assertEqual(keys, {}, "Expected empty dict with missing persp server sig")

        # remove the origin server's signature
        response = build_response()
        del response["signatures"][SERVER_NAME]
        keys = get_key_from_perspectives(response)
        self.assertEqual(keys, {}, "Expected empty dict with missing origin server sig")


def get_key_id(key):
    """Get the matrix ID tag for a given SigningKey or VerifyKey"""
    return "%s:%s" % (key.alg, key.version)


@defer.inlineCallbacks
def run_in_context(f, *args, **kwargs):
    with LoggingContext("testctx"):
        rv = yield f(*args, **kwargs)
    return rv


def _verify_json_for_server(kr, *args):
    """thin wrapper around verify_json_for_server which makes sure it is wrapped
    with the patched defer.inlineCallbacks.
    """

    @defer.inlineCallbacks
    def v():
        rv1 = yield kr.verify_json_for_server(*args)
        return rv1

    return run_in_context(v)
