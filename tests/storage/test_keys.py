# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

import signedjson.key

from twisted.internet import defer

import tests.unittest
import tests.utils


class KeyStoreTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(KeyStoreTestCase, self).__init__(*args, **kwargs)
        self.store = None  # type: synapse.storage.keys.KeyStore

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver(self.addCleanup)
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def test_get_server_verify_keys(self):
        key1 = signedjson.key.decode_verify_key_base64(
            "ed25519", "key1", "fP5l4JzpZPq/zdbBg5xx6lQGAAOM9/3w94cqiJ5jPrw"
        )
        key2 = signedjson.key.decode_verify_key_base64(
            "ed25519", "key2", "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw"
        )
        yield self.store.store_server_verify_key("server1", "from_server", 0, key1)
        yield self.store.store_server_verify_key("server1", "from_server", 0, key2)

        res = yield self.store.get_server_verify_keys(
            "server1", ["ed25519:key1", "ed25519:key2", "ed25519:key3"]
        )

        self.assertEqual(len(res.keys()), 2)
        self.assertEqual(res["ed25519:key1"].version, "key1")
        self.assertEqual(res["ed25519:key2"].version, "key2")
