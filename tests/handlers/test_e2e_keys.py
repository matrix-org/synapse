# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import mock

import signedjson.key as key
import signedjson.sign as sign

from twisted.internet import defer

import synapse.handlers.e2e_keys
import synapse.storage
from synapse.api import errors

from tests import unittest, utils


class E2eKeysHandlerTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(E2eKeysHandlerTestCase, self).__init__(*args, **kwargs)
        self.hs = None  # type: synapse.server.HomeServer
        self.handler = None  # type: synapse.handlers.e2e_keys.E2eKeysHandler

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield utils.setup_test_homeserver(
            self.addCleanup, handlers=None, federation_client=mock.Mock()
        )
        self.handler = synapse.handlers.e2e_keys.E2eKeysHandler(self.hs)

    @defer.inlineCallbacks
    def test_query_local_devices_no_devices(self):
        """If the user has no devices, we expect an empty list.
        """
        local_user = "@boris:" + self.hs.hostname
        res = yield self.handler.query_local_devices({local_user: None})
        self.assertDictEqual(res, {local_user: {}})

    @defer.inlineCallbacks
    def test_reupload_one_time_keys(self):
        """we should be able to re-upload the same keys"""
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {
            "alg1:k1": "key1",
            "alg2:k2": {"key": "key2", "signatures": {"k1": "sig1"}},
            "alg2:k3": {"key": "key3"},
        }

        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1, "alg2": 2}})

        # we should be able to change the signature without a problem
        keys["alg2:k2"]["signatures"]["k1"] = "sig2"
        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1, "alg2": 2}})

    @defer.inlineCallbacks
    def test_change_one_time_keys(self):
        """attempts to change one-time-keys should be rejected"""

        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {
            "alg1:k1": "key1",
            "alg2:k2": {"key": "key2", "signatures": {"k1": "sig1"}},
            "alg2:k3": {"key": "key3"},
        }

        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1, "alg2": 2}})

        try:
            yield self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg1:k1": "key2"}}
            )
            self.fail("No error when changing string key")
        except errors.SynapseError:
            pass

        try:
            yield self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg2:k3": "key2"}}
            )
            self.fail("No error when replacing dict key with string")
        except errors.SynapseError:
            pass

        try:
            yield self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg1:k1": {"key": "key"}}}
            )
            self.fail("No error when replacing string key with dict")
        except errors.SynapseError:
            pass

        try:
            yield self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {
                    "one_time_keys": {
                        "alg2:k2": {"key": "key3", "signatures": {"k1": "sig1"}}
                    }
                },
            )
            self.fail("No error when replacing dict key")
        except errors.SynapseError:
            pass

    @defer.inlineCallbacks
    def test_claim_one_time_key(self):
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {"alg1:k1": "key1"}

        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1}})

        res2 = yield self.handler.claim_one_time_keys(
            {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
        )
        self.assertEqual(
            res2,
            {
                "failures": {},
                "one_time_keys": {local_user: {device_id: {"alg1:k1": "key1"}}},
            },
        )

    @defer.inlineCallbacks
    def test_replace_master_key(self):
        """uploading a new signing key should make the old signing key unavailable"""
        local_user = "@boris:" + self.hs.hostname
        keys1 = {
            "master_key": {
                # private key: 2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk": "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
                },
            }
        }
        yield self.handler.upload_signing_keys_for_user(local_user, keys1)

        keys2 = {
            "master_key": {
                # private key: 4TL4AjRYwDVwD3pqQzcor+ez/euOB1/q78aTJ+czDNs
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:Hq6gL+utB4ET+UvD5ci0kgAwsX6qP/zvf8v6OInU5iw": "Hq6gL+utB4ET+UvD5ci0kgAwsX6qP/zvf8v6OInU5iw"
                },
            }
        }
        yield self.handler.upload_signing_keys_for_user(local_user, keys2)

        devices = yield self.handler.query_devices(
            {"device_keys": {local_user: []}}, 0, local_user
        )
        self.assertDictEqual(devices["master_keys"], {local_user: keys2["master_key"]})

    @defer.inlineCallbacks
    def test_reupload_signatures(self):
        """re-uploading a signature should not fail"""
        local_user = "@boris:" + self.hs.hostname
        keys1 = {
            "master_key": {
                # private key: HvQBbU+hc2Zr+JP1sE0XwBe1pfZZEYtJNPJLZJtS+F8
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:EmkqvokUn8p+vQAGZitOk4PWjp7Ukp3txV2TbMPEiBQ": "EmkqvokUn8p+vQAGZitOk4PWjp7Ukp3txV2TbMPEiBQ"
                },
            },
            "self_signing_key": {
                # private key: 2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0
                "user_id": local_user,
                "usage": ["self_signing"],
                "keys": {
                    "ed25519:nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk": "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
                },
            },
        }
        master_signing_key = key.decode_signing_key_base64(
            "ed25519",
            "EmkqvokUn8p+vQAGZitOk4PWjp7Ukp3txV2TbMPEiBQ",
            "HvQBbU+hc2Zr+JP1sE0XwBe1pfZZEYtJNPJLZJtS+F8",
        )
        sign.sign_json(keys1["self_signing_key"], local_user, master_signing_key)
        signing_key = key.decode_signing_key_base64(
            "ed25519",
            "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk",
            "2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0",
        )
        yield self.handler.upload_signing_keys_for_user(local_user, keys1)

        # upload two device keys, which will be signed later by the self-signing key
        device_key_1 = {
            "user_id": local_user,
            "device_id": "abc",
            "algorithms": ["m.olm.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
            "keys": {
                "ed25519:abc": "base64+ed25519+key",
                "curve25519:abc": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:abc": "base64+signature"}},
        }
        device_key_2 = {
            "user_id": local_user,
            "device_id": "def",
            "algorithms": ["m.olm.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
            "keys": {
                "ed25519:def": "base64+ed25519+key",
                "curve25519:def": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:def": "base64+signature"}},
        }

        yield self.handler.upload_keys_for_user(
            local_user, "abc", {"device_keys": device_key_1}
        )
        yield self.handler.upload_keys_for_user(
            local_user, "def", {"device_keys": device_key_2}
        )

        # sign the first device key and upload it
        del device_key_1["signatures"]
        sign.sign_json(device_key_1, local_user, signing_key)
        yield self.handler.upload_signatures_for_device_keys(
            local_user, {local_user: {"abc": device_key_1}}
        )

        # sign the second device key and upload both device keys.  The server
        # should ignore the first device key since it already has a valid
        # signature for it
        del device_key_2["signatures"]
        sign.sign_json(device_key_2, local_user, signing_key)
        yield self.handler.upload_signatures_for_device_keys(
            local_user, {local_user: {"abc": device_key_1, "def": device_key_2}}
        )

        device_key_1["signatures"][local_user]["ed25519:abc"] = "base64+signature"
        device_key_2["signatures"][local_user]["ed25519:def"] = "base64+signature"
        devices = yield self.handler.query_devices(
            {"device_keys": {local_user: []}}, 0, local_user
        )
        del devices["device_keys"][local_user]["abc"]["unsigned"]
        del devices["device_keys"][local_user]["def"]["unsigned"]
        self.assertDictEqual(devices["device_keys"][local_user]["abc"], device_key_1)
        self.assertDictEqual(devices["device_keys"][local_user]["def"], device_key_2)

    @defer.inlineCallbacks
    def test_self_signing_key_doesnt_show_up_as_device(self):
        """signing keys should be hidden when fetching a user's devices"""
        local_user = "@boris:" + self.hs.hostname
        keys1 = {
            "master_key": {
                # private key: 2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk": "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
                },
            }
        }
        yield self.handler.upload_signing_keys_for_user(local_user, keys1)

        res = None
        try:
            yield self.hs.get_device_handler().check_device_registered(
                user_id=local_user,
                device_id="nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk",
                initial_device_display_name="new display name",
            )
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 400)

        res = yield self.handler.query_local_devices({local_user: None})
        self.assertDictEqual(res, {local_user: {}})

    @defer.inlineCallbacks
    def test_upload_signatures(self):
        """should check signatures that are uploaded"""
        # set up a user with cross-signing keys and a device.  This user will
        # try uploading signatures
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        # private key: OMkooTr76ega06xNvXIGPbgvvxAOzmQncN8VObS7aBA
        device_pubkey = "NnHhnqiMFQkq969szYkooLaBAXW244ZOxgukCvm2ZeY"
        device_key = {
            "user_id": local_user,
            "device_id": device_id,
            "algorithms": ["m.olm.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
            "keys": {"curve25519:xyz": "curve25519+key", "ed25519:xyz": device_pubkey},
            "signatures": {local_user: {"ed25519:xyz": "something"}},
        }
        device_signing_key = key.decode_signing_key_base64(
            "ed25519", "xyz", "OMkooTr76ega06xNvXIGPbgvvxAOzmQncN8VObS7aBA"
        )

        yield self.handler.upload_keys_for_user(
            local_user, device_id, {"device_keys": device_key}
        )

        # private key: 2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0
        master_pubkey = "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
        master_key = {
            "user_id": local_user,
            "usage": ["master"],
            "keys": {"ed25519:" + master_pubkey: master_pubkey},
        }
        master_signing_key = key.decode_signing_key_base64(
            "ed25519", master_pubkey, "2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0"
        )
        usersigning_pubkey = "Hq6gL+utB4ET+UvD5ci0kgAwsX6qP/zvf8v6OInU5iw"
        usersigning_key = {
            # private key: 4TL4AjRYwDVwD3pqQzcor+ez/euOB1/q78aTJ+czDNs
            "user_id": local_user,
            "usage": ["user_signing"],
            "keys": {"ed25519:" + usersigning_pubkey: usersigning_pubkey},
        }
        usersigning_signing_key = key.decode_signing_key_base64(
            "ed25519", usersigning_pubkey, "4TL4AjRYwDVwD3pqQzcor+ez/euOB1/q78aTJ+czDNs"
        )
        sign.sign_json(usersigning_key, local_user, master_signing_key)
        # private key: HvQBbU+hc2Zr+JP1sE0XwBe1pfZZEYtJNPJLZJtS+F8
        selfsigning_pubkey = "EmkqvokUn8p+vQAGZitOk4PWjp7Ukp3txV2TbMPEiBQ"
        selfsigning_key = {
            "user_id": local_user,
            "usage": ["self_signing"],
            "keys": {"ed25519:" + selfsigning_pubkey: selfsigning_pubkey},
        }
        selfsigning_signing_key = key.decode_signing_key_base64(
            "ed25519", selfsigning_pubkey, "HvQBbU+hc2Zr+JP1sE0XwBe1pfZZEYtJNPJLZJtS+F8"
        )
        sign.sign_json(selfsigning_key, local_user, master_signing_key)
        cross_signing_keys = {
            "master_key": master_key,
            "user_signing_key": usersigning_key,
            "self_signing_key": selfsigning_key,
        }
        yield self.handler.upload_signing_keys_for_user(local_user, cross_signing_keys)

        # set up another user with a master key.  This user will be signed by
        # the first user
        other_user = "@otherboris:" + self.hs.hostname
        other_master_pubkey = "fHZ3NPiKxoLQm5OoZbKa99SYxprOjNs4TwJUKP+twCM"
        other_master_key = {
            # private key: oyw2ZUx0O4GifbfFYM0nQvj9CL0b8B7cyN4FprtK8OI
            "user_id": other_user,
            "usage": ["master"],
            "keys": {"ed25519:" + other_master_pubkey: other_master_pubkey},
        }
        yield self.handler.upload_signing_keys_for_user(
            other_user, {"master_key": other_master_key}
        )

        # test various signature failures (see below)
        ret = yield self.handler.upload_signatures_for_device_keys(
            local_user,
            {
                local_user: {
                    # fails because the signature is invalid
                    # should fail with INVALID_SIGNATURE
                    device_id: {
                        "user_id": local_user,
                        "device_id": device_id,
                        "algorithms": [
                            "m.olm.curve25519-aes-sha2",
                            "m.megolm.v1.aes-sha2",
                        ],
                        "keys": {
                            "curve25519:xyz": "curve25519+key",
                            # private key: OMkooTr76ega06xNvXIGPbgvvxAOzmQncN8VObS7aBA
                            "ed25519:xyz": device_pubkey,
                        },
                        "signatures": {
                            local_user: {"ed25519:" + selfsigning_pubkey: "something"}
                        },
                    },
                    # fails because device is unknown
                    # should fail with NOT_FOUND
                    "unknown": {
                        "user_id": local_user,
                        "device_id": "unknown",
                        "signatures": {
                            local_user: {"ed25519:" + selfsigning_pubkey: "something"}
                        },
                    },
                    # fails because the signature is invalid
                    # should fail with INVALID_SIGNATURE
                    master_pubkey: {
                        "user_id": local_user,
                        "usage": ["master"],
                        "keys": {"ed25519:" + master_pubkey: master_pubkey},
                        "signatures": {
                            local_user: {"ed25519:" + device_pubkey: "something"}
                        },
                    },
                },
                other_user: {
                    # fails because the device is not the user's master-signing key
                    # should fail with NOT_FOUND
                    "unknown": {
                        "user_id": other_user,
                        "device_id": "unknown",
                        "signatures": {
                            local_user: {"ed25519:" + usersigning_pubkey: "something"}
                        },
                    },
                    other_master_pubkey: {
                        # fails because the key doesn't match what the server has
                        # should fail with UNKNOWN
                        "user_id": other_user,
                        "usage": ["master"],
                        "keys": {"ed25519:" + other_master_pubkey: other_master_pubkey},
                        "something": "random",
                        "signatures": {
                            local_user: {"ed25519:" + usersigning_pubkey: "something"}
                        },
                    },
                },
            },
        )

        user_failures = ret["failures"][local_user]
        self.assertEqual(
            user_failures[device_id]["errcode"], errors.Codes.INVALID_SIGNATURE
        )
        self.assertEqual(
            user_failures[master_pubkey]["errcode"], errors.Codes.INVALID_SIGNATURE
        )
        self.assertEqual(user_failures["unknown"]["errcode"], errors.Codes.NOT_FOUND)

        other_user_failures = ret["failures"][other_user]
        self.assertEqual(
            other_user_failures["unknown"]["errcode"], errors.Codes.NOT_FOUND
        )
        self.assertEqual(
            other_user_failures[other_master_pubkey]["errcode"], errors.Codes.UNKNOWN
        )

        # test successful signatures
        del device_key["signatures"]
        sign.sign_json(device_key, local_user, selfsigning_signing_key)
        sign.sign_json(master_key, local_user, device_signing_key)
        sign.sign_json(other_master_key, local_user, usersigning_signing_key)
        ret = yield self.handler.upload_signatures_for_device_keys(
            local_user,
            {
                local_user: {device_id: device_key, master_pubkey: master_key},
                other_user: {other_master_pubkey: other_master_key},
            },
        )

        self.assertEqual(ret["failures"], {})

        # fetch the signed keys/devices and make sure that the signatures are there
        ret = yield self.handler.query_devices(
            {"device_keys": {local_user: [], other_user: []}}, 0, local_user
        )

        self.assertEqual(
            ret["device_keys"][local_user]["xyz"]["signatures"][local_user][
                "ed25519:" + selfsigning_pubkey
            ],
            device_key["signatures"][local_user]["ed25519:" + selfsigning_pubkey],
        )
        self.assertEqual(
            ret["master_keys"][local_user]["signatures"][local_user][
                "ed25519:" + device_id
            ],
            master_key["signatures"][local_user]["ed25519:" + device_id],
        )
        self.assertEqual(
            ret["master_keys"][other_user]["signatures"][local_user][
                "ed25519:" + usersigning_pubkey
            ],
            other_master_key["signatures"][local_user]["ed25519:" + usersigning_pubkey],
        )
