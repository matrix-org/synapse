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
from typing import Iterable
from unittest import mock

from parameterized import parameterized
from signedjson import key as key, sign as sign

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import RoomEncryptionAlgorithms
from synapse.api.errors import Codes, SynapseError
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest
from tests.test_utils import make_awaitable


class E2eKeysHandlerTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        return self.setup_test_homeserver(federation_client=mock.Mock())

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.handler = hs.get_e2e_keys_handler()
        self.store = self.hs.get_datastores().main

    def test_query_local_devices_no_devices(self) -> None:
        """If the user has no devices, we expect an empty list."""
        local_user = "@boris:" + self.hs.hostname
        res = self.get_success(self.handler.query_local_devices({local_user: None}))
        self.assertDictEqual(res, {local_user: {}})

    def test_reupload_one_time_keys(self) -> None:
        """we should be able to re-upload the same keys"""
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys: JsonDict = {
            "alg1:k1": "key1",
            "alg2:k2": {"key": "key2", "signatures": {"k1": "sig1"}},
            "alg2:k3": {"key": "key3"},
        }

        # Note that "signed_curve25519" is always returned in key count responses. This is necessary until
        # https://github.com/matrix-org/matrix-doc/issues/3298 is fixed.
        res = self.get_success(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": keys}
            )
        )
        self.assertDictEqual(
            res, {"one_time_key_counts": {"alg1": 1, "alg2": 2, "signed_curve25519": 0}}
        )

        # we should be able to change the signature without a problem
        keys["alg2:k2"]["signatures"]["k1"] = "sig2"
        res = self.get_success(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": keys}
            )
        )
        self.assertDictEqual(
            res, {"one_time_key_counts": {"alg1": 1, "alg2": 2, "signed_curve25519": 0}}
        )

    def test_change_one_time_keys(self) -> None:
        """attempts to change one-time-keys should be rejected"""

        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {
            "alg1:k1": "key1",
            "alg2:k2": {"key": "key2", "signatures": {"k1": "sig1"}},
            "alg2:k3": {"key": "key3"},
        }

        res = self.get_success(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": keys}
            )
        )
        self.assertDictEqual(
            res, {"one_time_key_counts": {"alg1": 1, "alg2": 2, "signed_curve25519": 0}}
        )

        # Error when changing string key
        self.get_failure(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg1:k1": "key2"}}
            ),
            SynapseError,
        )

        # Error when replacing dict key with string
        self.get_failure(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg2:k3": "key2"}}
            ),
            SynapseError,
        )

        # Error when replacing string key with dict
        self.get_failure(
            self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {"one_time_keys": {"alg1:k1": {"key": "key"}}},
            ),
            SynapseError,
        )

        # Error when replacing dict key
        self.get_failure(
            self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {
                    "one_time_keys": {
                        "alg2:k2": {"key": "key3", "signatures": {"k1": "sig1"}}
                    }
                },
            ),
            SynapseError,
        )

    def test_claim_one_time_key(self) -> None:
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {"alg1:k1": "key1"}

        res = self.get_success(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": keys}
            )
        )
        self.assertDictEqual(
            res, {"one_time_key_counts": {"alg1": 1, "signed_curve25519": 0}}
        )

        res2 = self.get_success(
            self.handler.claim_one_time_keys(
                {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
            )
        )
        self.assertEqual(
            res2,
            {
                "failures": {},
                "one_time_keys": {local_user: {device_id: {"alg1:k1": "key1"}}},
            },
        )

    def test_fallback_key(self) -> None:
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        fallback_key = {"alg1:k1": "fallback_key1"}
        fallback_key2 = {"alg1:k2": "fallback_key2"}
        fallback_key3 = {"alg1:k2": "fallback_key3"}
        otk = {"alg1:k2": "key2"}

        # we shouldn't have any unused fallback keys yet
        res = self.get_success(
            self.store.get_e2e_unused_fallback_key_types(local_user, device_id)
        )
        self.assertEqual(res, [])

        self.get_success(
            self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {"fallback_keys": fallback_key},
            )
        )

        # we should now have an unused alg1 key
        res = self.get_success(
            self.store.get_e2e_unused_fallback_key_types(local_user, device_id)
        )
        self.assertEqual(res, ["alg1"])

        # claiming an OTK when no OTKs are available should return the fallback
        # key
        res = self.get_success(
            self.handler.claim_one_time_keys(
                {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
            )
        )
        self.assertEqual(
            res,
            {"failures": {}, "one_time_keys": {local_user: {device_id: fallback_key}}},
        )

        # we shouldn't have any unused fallback keys again
        res = self.get_success(
            self.store.get_e2e_unused_fallback_key_types(local_user, device_id)
        )
        self.assertEqual(res, [])

        # claiming an OTK again should return the same fallback key
        res = self.get_success(
            self.handler.claim_one_time_keys(
                {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
            )
        )
        self.assertEqual(
            res,
            {"failures": {}, "one_time_keys": {local_user: {device_id: fallback_key}}},
        )

        # re-uploading the same fallback key should still result in no unused fallback
        # keys
        self.get_success(
            self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {"fallback_keys": fallback_key},
            )
        )

        res = self.get_success(
            self.store.get_e2e_unused_fallback_key_types(local_user, device_id)
        )
        self.assertEqual(res, [])

        # uploading a new fallback key should result in an unused fallback key
        self.get_success(
            self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {"fallback_keys": fallback_key2},
            )
        )

        res = self.get_success(
            self.store.get_e2e_unused_fallback_key_types(local_user, device_id)
        )
        self.assertEqual(res, ["alg1"])

        # if the user uploads a one-time key, the next claim should fetch the
        # one-time key, and then go back to the fallback
        self.get_success(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": otk}
            )
        )

        res = self.get_success(
            self.handler.claim_one_time_keys(
                {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
            )
        )
        self.assertEqual(
            res,
            {"failures": {}, "one_time_keys": {local_user: {device_id: otk}}},
        )

        res = self.get_success(
            self.handler.claim_one_time_keys(
                {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
            )
        )
        self.assertEqual(
            res,
            {"failures": {}, "one_time_keys": {local_user: {device_id: fallback_key2}}},
        )

        # using the unstable prefix should also set the fallback key
        self.get_success(
            self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {"org.matrix.msc2732.fallback_keys": fallback_key3},
            )
        )

        res = self.get_success(
            self.handler.claim_one_time_keys(
                {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
            )
        )
        self.assertEqual(
            res,
            {"failures": {}, "one_time_keys": {local_user: {device_id: fallback_key3}}},
        )

    def test_replace_master_key(self) -> None:
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
        self.get_success(self.handler.upload_signing_keys_for_user(local_user, keys1))

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
        self.get_success(self.handler.upload_signing_keys_for_user(local_user, keys2))

        devices = self.get_success(
            self.handler.query_devices(
                {"device_keys": {local_user: []}}, 0, local_user, "device123"
            )
        )
        self.assertDictEqual(devices["master_keys"], {local_user: keys2["master_key"]})

    def test_reupload_signatures(self) -> None:
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
        self.get_success(self.handler.upload_signing_keys_for_user(local_user, keys1))

        # upload two device keys, which will be signed later by the self-signing key
        device_key_1 = {
            "user_id": local_user,
            "device_id": "abc",
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
            ],
            "keys": {
                "ed25519:abc": "base64+ed25519+key",
                "curve25519:abc": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:abc": "base64+signature"}},
        }
        device_key_2 = {
            "user_id": local_user,
            "device_id": "def",
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
            ],
            "keys": {
                "ed25519:def": "base64+ed25519+key",
                "curve25519:def": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:def": "base64+signature"}},
        }

        self.get_success(
            self.handler.upload_keys_for_user(
                local_user, "abc", {"device_keys": device_key_1}
            )
        )
        self.get_success(
            self.handler.upload_keys_for_user(
                local_user, "def", {"device_keys": device_key_2}
            )
        )

        # sign the first device key and upload it
        del device_key_1["signatures"]
        sign.sign_json(device_key_1, local_user, signing_key)
        self.get_success(
            self.handler.upload_signatures_for_device_keys(
                local_user, {local_user: {"abc": device_key_1}}
            )
        )

        # sign the second device key and upload both device keys.  The server
        # should ignore the first device key since it already has a valid
        # signature for it
        del device_key_2["signatures"]
        sign.sign_json(device_key_2, local_user, signing_key)
        self.get_success(
            self.handler.upload_signatures_for_device_keys(
                local_user, {local_user: {"abc": device_key_1, "def": device_key_2}}
            )
        )

        device_key_1["signatures"][local_user]["ed25519:abc"] = "base64+signature"
        device_key_2["signatures"][local_user]["ed25519:def"] = "base64+signature"
        devices = self.get_success(
            self.handler.query_devices(
                {"device_keys": {local_user: []}}, 0, local_user, "device123"
            )
        )
        del devices["device_keys"][local_user]["abc"]["unsigned"]
        del devices["device_keys"][local_user]["def"]["unsigned"]
        self.assertDictEqual(devices["device_keys"][local_user]["abc"], device_key_1)
        self.assertDictEqual(devices["device_keys"][local_user]["def"], device_key_2)

    def test_self_signing_key_doesnt_show_up_as_device(self) -> None:
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
        self.get_success(self.handler.upload_signing_keys_for_user(local_user, keys1))

        e = self.get_failure(
            self.hs.get_device_handler().check_device_registered(
                user_id=local_user,
                device_id="nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk",
                initial_device_display_name="new display name",
            ),
            SynapseError,
        )
        res = e.value.code
        self.assertEqual(res, 400)

        query_res = self.get_success(
            self.handler.query_local_devices({local_user: None})
        )
        self.assertDictEqual(query_res, {local_user: {}})

    def test_upload_signatures(self) -> None:
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
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
            ],
            "keys": {"curve25519:xyz": "curve25519+key", "ed25519:xyz": device_pubkey},
            "signatures": {local_user: {"ed25519:xyz": "something"}},
        }
        device_signing_key = key.decode_signing_key_base64(
            "ed25519", "xyz", "OMkooTr76ega06xNvXIGPbgvvxAOzmQncN8VObS7aBA"
        )

        self.get_success(
            self.handler.upload_keys_for_user(
                local_user, device_id, {"device_keys": device_key}
            )
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
        self.get_success(
            self.handler.upload_signing_keys_for_user(local_user, cross_signing_keys)
        )

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
        self.get_success(
            self.handler.upload_signing_keys_for_user(
                other_user, {"master_key": other_master_key}
            )
        )

        # test various signature failures (see below)
        ret = self.get_success(
            self.handler.upload_signatures_for_device_keys(
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
                                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
                            ],
                            "keys": {
                                "curve25519:xyz": "curve25519+key",
                                # private key: OMkooTr76ega06xNvXIGPbgvvxAOzmQncN8VObS7aBA
                                "ed25519:xyz": device_pubkey,
                            },
                            "signatures": {
                                local_user: {
                                    "ed25519:" + selfsigning_pubkey: "something"
                                }
                            },
                        },
                        # fails because device is unknown
                        # should fail with NOT_FOUND
                        "unknown": {
                            "user_id": local_user,
                            "device_id": "unknown",
                            "signatures": {
                                local_user: {
                                    "ed25519:" + selfsigning_pubkey: "something"
                                }
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
                                local_user: {
                                    "ed25519:" + usersigning_pubkey: "something"
                                }
                            },
                        },
                        other_master_pubkey: {
                            # fails because the key doesn't match what the server has
                            # should fail with UNKNOWN
                            "user_id": other_user,
                            "usage": ["master"],
                            "keys": {
                                "ed25519:" + other_master_pubkey: other_master_pubkey
                            },
                            "something": "random",
                            "signatures": {
                                local_user: {
                                    "ed25519:" + usersigning_pubkey: "something"
                                }
                            },
                        },
                    },
                },
            )
        )

        user_failures = ret["failures"][local_user]
        self.assertEqual(user_failures[device_id]["errcode"], Codes.INVALID_SIGNATURE)
        self.assertEqual(
            user_failures[master_pubkey]["errcode"], Codes.INVALID_SIGNATURE
        )
        self.assertEqual(user_failures["unknown"]["errcode"], Codes.NOT_FOUND)

        other_user_failures = ret["failures"][other_user]
        self.assertEqual(other_user_failures["unknown"]["errcode"], Codes.NOT_FOUND)
        self.assertEqual(
            other_user_failures[other_master_pubkey]["errcode"], Codes.UNKNOWN
        )

        # test successful signatures
        del device_key["signatures"]
        sign.sign_json(device_key, local_user, selfsigning_signing_key)
        sign.sign_json(master_key, local_user, device_signing_key)
        sign.sign_json(other_master_key, local_user, usersigning_signing_key)
        ret = self.get_success(
            self.handler.upload_signatures_for_device_keys(
                local_user,
                {
                    local_user: {device_id: device_key, master_pubkey: master_key},
                    other_user: {other_master_pubkey: other_master_key},
                },
            )
        )

        self.assertEqual(ret["failures"], {})

        # fetch the signed keys/devices and make sure that the signatures are there
        ret = self.get_success(
            self.handler.query_devices(
                {"device_keys": {local_user: [], other_user: []}},
                0,
                local_user,
                "device123",
            )
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

    def test_query_devices_remote_no_sync(self) -> None:
        """Tests that querying keys for a remote user that we don't share a room
        with returns the cross signing keys correctly.
        """

        remote_user_id = "@test:other"
        local_user_id = "@test:test"

        remote_master_key = "85T7JXPFBAySB/jwby4S3lBPTqY3+Zg53nYuGmu1ggY"
        remote_self_signing_key = "QeIiFEjluPBtI7WQdG365QKZcFs9kqmHir6RBD0//nQ"

        self.hs.get_federation_client().query_client_keys = mock.Mock(
            return_value=make_awaitable(
                {
                    "device_keys": {remote_user_id: {}},
                    "master_keys": {
                        remote_user_id: {
                            "user_id": remote_user_id,
                            "usage": ["master"],
                            "keys": {"ed25519:" + remote_master_key: remote_master_key},
                        },
                    },
                    "self_signing_keys": {
                        remote_user_id: {
                            "user_id": remote_user_id,
                            "usage": ["self_signing"],
                            "keys": {
                                "ed25519:"
                                + remote_self_signing_key: remote_self_signing_key
                            },
                        }
                    },
                }
            )
        )

        e2e_handler = self.hs.get_e2e_keys_handler()

        query_result = self.get_success(
            e2e_handler.query_devices(
                {
                    "device_keys": {remote_user_id: []},
                },
                timeout=10,
                from_user_id=local_user_id,
                from_device_id="some_device_id",
            )
        )

        self.assertEqual(query_result["failures"], {})
        self.assertEqual(
            query_result["master_keys"],
            {
                remote_user_id: {
                    "user_id": remote_user_id,
                    "usage": ["master"],
                    "keys": {"ed25519:" + remote_master_key: remote_master_key},
                },
            },
        )
        self.assertEqual(
            query_result["self_signing_keys"],
            {
                remote_user_id: {
                    "user_id": remote_user_id,
                    "usage": ["self_signing"],
                    "keys": {
                        "ed25519:" + remote_self_signing_key: remote_self_signing_key
                    },
                }
            },
        )

    def test_query_devices_remote_sync(self) -> None:
        """Tests that querying keys for a remote user that we share a room with,
        but haven't yet fetched the keys for, returns the cross signing keys
        correctly.
        """

        remote_user_id = "@test:other"
        local_user_id = "@test:test"

        # Pretend we're sharing a room with the user we're querying. If not,
        # `_query_devices_for_destination` will return early.
        self.store.get_rooms_for_user = mock.Mock(
            return_value=make_awaitable({"some_room_id"})
        )

        remote_master_key = "85T7JXPFBAySB/jwby4S3lBPTqY3+Zg53nYuGmu1ggY"
        remote_self_signing_key = "QeIiFEjluPBtI7WQdG365QKZcFs9kqmHir6RBD0//nQ"

        self.hs.get_federation_client().query_user_devices = mock.Mock(
            return_value=make_awaitable(
                {
                    "user_id": remote_user_id,
                    "stream_id": 1,
                    "devices": [],
                    "master_key": {
                        "user_id": remote_user_id,
                        "usage": ["master"],
                        "keys": {"ed25519:" + remote_master_key: remote_master_key},
                    },
                    "self_signing_key": {
                        "user_id": remote_user_id,
                        "usage": ["self_signing"],
                        "keys": {
                            "ed25519:"
                            + remote_self_signing_key: remote_self_signing_key
                        },
                    },
                }
            )
        )

        e2e_handler = self.hs.get_e2e_keys_handler()

        query_result = self.get_success(
            e2e_handler.query_devices(
                {
                    "device_keys": {remote_user_id: []},
                },
                timeout=10,
                from_user_id=local_user_id,
                from_device_id="some_device_id",
            )
        )

        self.assertEqual(query_result["failures"], {})
        self.assertEqual(
            query_result["master_keys"],
            {
                remote_user_id: {
                    "user_id": remote_user_id,
                    "usage": ["master"],
                    "keys": {"ed25519:" + remote_master_key: remote_master_key},
                }
            },
        )
        self.assertEqual(
            query_result["self_signing_keys"],
            {
                remote_user_id: {
                    "user_id": remote_user_id,
                    "usage": ["self_signing"],
                    "keys": {
                        "ed25519:" + remote_self_signing_key: remote_self_signing_key
                    },
                }
            },
        )

    @parameterized.expand(
        [
            # The remote homeserver's response indicates that this user has 0/1/2 devices.
            ([],),
            (["device_1"],),
            (["device_1", "device_2"],),
        ]
    )
    def test_query_all_devices_caches_result(self, device_ids: Iterable[str]) -> None:
        """Test that requests for all of a remote user's devices are cached.

        We do this by asserting that only one call over federation was made, and that
        the two queries to the local homeserver produce the same response.
        """
        local_user_id = "@test:test"
        remote_user_id = "@test:other"
        request_body: JsonDict = {"device_keys": {remote_user_id: []}}

        response_devices = [
            {
                "device_id": device_id,
                "keys": {
                    "algorithms": ["dummy"],
                    "device_id": device_id,
                    "keys": {f"dummy:{device_id}": "dummy"},
                    "signatures": {device_id: {f"dummy:{device_id}": "dummy"}},
                    "unsigned": {},
                    "user_id": "@test:other",
                },
            }
            for device_id in device_ids
        ]

        response_body = {
            "devices": response_devices,
            "user_id": remote_user_id,
            "stream_id": 12345,  # an integer, according to the spec
        }

        e2e_handler = self.hs.get_e2e_keys_handler()

        # Pretend we're sharing a room with the user we're querying. If not,
        # `_query_devices_for_destination` will return early.
        mock_get_rooms = mock.patch.object(
            self.store,
            "get_rooms_for_user",
            new_callable=mock.MagicMock,
            return_value=make_awaitable(["some_room_id"]),
        )
        mock_request = mock.patch.object(
            self.hs.get_federation_client(),
            "query_user_devices",
            new_callable=mock.MagicMock,
            return_value=make_awaitable(response_body),
        )

        with mock_get_rooms, mock_request as mocked_federation_request:
            # Make the first query and sanity check it succeeds.
            response_1 = self.get_success(
                e2e_handler.query_devices(
                    request_body,
                    timeout=10,
                    from_user_id=local_user_id,
                    from_device_id="some_device_id",
                )
            )
            self.assertEqual(response_1["failures"], {})

            # We should have made a federation request to do so.
            mocked_federation_request.assert_called_once()

            # Reset the mock so we can prove we don't make a second federation request.
            mocked_federation_request.reset_mock()

            # Repeat the query.
            response_2 = self.get_success(
                e2e_handler.query_devices(
                    request_body,
                    timeout=10,
                    from_user_id=local_user_id,
                    from_device_id="some_device_id",
                )
            )
            self.assertEqual(response_2["failures"], {})

            # We should not have made a second federation request.
            mocked_federation_request.assert_not_called()

            # The two requests to the local homeserver should be identical.
            self.assertEqual(response_1, response_2)
