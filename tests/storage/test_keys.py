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

from twisted.internet.defer import Deferred

import tests.unittest

KEY_1 = signedjson.key.decode_verify_key_base64(
    "ed25519", "key1", "fP5l4JzpZPq/zdbBg5xx6lQGAAOM9/3w94cqiJ5jPrw"
)
KEY_2 = signedjson.key.decode_verify_key_base64(
    "ed25519", "key2", "Noi6WqcDj0QmPxCNQqgezwTlBKrfqehY1u2FyWP9uYw"
)


class KeyStoreTestCase(tests.unittest.HomeserverTestCase):
    def test_get_server_verify_keys(self):
        store = self.hs.get_datastore()

        d = store.store_server_verify_key("server1", "from_server", 0, KEY_1)
        self.get_success(d)
        d = store.store_server_verify_key("server1", "from_server", 0, KEY_2)
        self.get_success(d)

        d = store.get_server_verify_keys(
            [
                ("server1", "ed25519:key1"),
                ("server1", "ed25519:key2"),
                ("server1", "ed25519:key3"),
            ]
        )
        res = self.get_success(d)

        self.assertEqual(len(res.keys()), 3)
        self.assertEqual(res[("server1", "ed25519:key1")].version, "key1")
        self.assertEqual(res[("server1", "ed25519:key2")].version, "key2")

        # non-existent result gives None
        self.assertIsNone(res[("server1", "ed25519:key3")])

    def test_cache(self):
        """Check that updates correctly invalidate the cache."""

        store = self.hs.get_datastore()

        key_id_1 = "ed25519:key1"
        key_id_2 = "ed25519:key2"

        d = store.store_server_verify_key("srv1", "from_server", 0, KEY_1)
        self.get_success(d)
        d = store.store_server_verify_key("srv1", "from_server", 0, KEY_2)
        self.get_success(d)

        d = store.get_server_verify_keys([("srv1", key_id_1), ("srv1", key_id_2)])
        res = self.get_success(d)
        self.assertEqual(len(res.keys()), 2)
        self.assertEqual(res[("srv1", key_id_1)], KEY_1)
        self.assertEqual(res[("srv1", key_id_2)], KEY_2)

        # we should be able to look up the same thing again without a db hit
        res = store.get_server_verify_keys([("srv1", key_id_1)])
        if isinstance(res, Deferred):
            res = self.successResultOf(res)
        self.assertEqual(len(res.keys()), 1)
        self.assertEqual(res[("srv1", key_id_1)], KEY_1)

        new_key_2 = signedjson.key.get_verify_key(
            signedjson.key.generate_signing_key("key2")
        )
        d = store.store_server_verify_key("srv1", "from_server", 10, new_key_2)
        self.get_success(d)

        d = store.get_server_verify_keys([("srv1", key_id_1), ("srv1", key_id_2)])
        res = self.get_success(d)
        self.assertEqual(len(res.keys()), 2)
        self.assertEqual(res[("srv1", key_id_1)], KEY_1)
        self.assertEqual(res[("srv1", key_id_2)], new_key_2)
