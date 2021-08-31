# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
from typing import Optional
from unittest.mock import Mock

from signedjson import key, sign
from signedjson.types import BaseKey, SigningKey

from twisted.internet import defer

from synapse.api.constants import RoomEncryptionAlgorithms
from synapse.rest import admin
from synapse.rest.client.v1 import login
from synapse.types import JsonDict, ReadReceipt

from tests.test_utils import make_awaitable
from tests.unittest import HomeserverTestCase, override_config


class FederationSenderReceiptsTestCases(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        mock_state_handler = Mock(spec=["get_current_hosts_in_room"])
        # Ensure a new Awaitable is created for each call.
        mock_state_handler.get_current_hosts_in_room.return_value = make_awaitable(
            ["test", "host2"]
        )
        return self.setup_test_homeserver(
            state_handler=mock_state_handler,
            federation_transport_client=Mock(spec=["send_transaction"]),
        )

    @override_config({"send_federation": True})
    def test_send_receipts(self):
        mock_send_transaction = (
            self.hs.get_federation_transport_client().send_transaction
        )
        mock_send_transaction.return_value = make_awaitable({})

        sender = self.hs.get_federation_sender()
        receipt = ReadReceipt(
            "room_id", "m.read", "user_id", ["event_id"], {"ts": 1234}
        )
        self.successResultOf(defer.ensureDeferred(sender.send_read_receipt(receipt)))

        self.pump()

        # expect a call to send_transaction
        mock_send_transaction.assert_called_once()
        json_cb = mock_send_transaction.call_args[0][1]
        data = json_cb()
        self.assertEqual(
            data["edus"],
            [
                {
                    "edu_type": "m.receipt",
                    "content": {
                        "room_id": {
                            "m.read": {
                                "user_id": {
                                    "event_ids": ["event_id"],
                                    "data": {"ts": 1234},
                                }
                            }
                        }
                    },
                }
            ],
        )

    @override_config({"send_federation": True})
    def test_send_receipts_with_backoff(self):
        """Send two receipts in quick succession; the second should be flushed, but
        only after 20ms"""
        mock_send_transaction = (
            self.hs.get_federation_transport_client().send_transaction
        )
        mock_send_transaction.return_value = make_awaitable({})

        sender = self.hs.get_federation_sender()
        receipt = ReadReceipt(
            "room_id", "m.read", "user_id", ["event_id"], {"ts": 1234}
        )
        self.successResultOf(defer.ensureDeferred(sender.send_read_receipt(receipt)))

        self.pump()

        # expect a call to send_transaction
        mock_send_transaction.assert_called_once()
        json_cb = mock_send_transaction.call_args[0][1]
        data = json_cb()
        self.assertEqual(
            data["edus"],
            [
                {
                    "edu_type": "m.receipt",
                    "content": {
                        "room_id": {
                            "m.read": {
                                "user_id": {
                                    "event_ids": ["event_id"],
                                    "data": {"ts": 1234},
                                }
                            }
                        }
                    },
                }
            ],
        )
        mock_send_transaction.reset_mock()

        # send the second RR
        receipt = ReadReceipt(
            "room_id", "m.read", "user_id", ["other_id"], {"ts": 1234}
        )
        self.successResultOf(defer.ensureDeferred(sender.send_read_receipt(receipt)))
        self.pump()
        mock_send_transaction.assert_not_called()

        self.reactor.advance(19)
        mock_send_transaction.assert_not_called()

        self.reactor.advance(10)
        mock_send_transaction.assert_called_once()
        json_cb = mock_send_transaction.call_args[0][1]
        data = json_cb()
        self.assertEqual(
            data["edus"],
            [
                {
                    "edu_type": "m.receipt",
                    "content": {
                        "room_id": {
                            "m.read": {
                                "user_id": {
                                    "event_ids": ["other_id"],
                                    "data": {"ts": 1234},
                                }
                            }
                        }
                    },
                }
            ],
        )


class FederationSenderDevicesTestCases(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        return self.setup_test_homeserver(
            federation_transport_client=Mock(spec=["send_transaction"]),
        )

    def default_config(self):
        c = super().default_config()
        c["send_federation"] = True
        return c

    def prepare(self, reactor, clock, hs):
        # stub out get_users_who_share_room_with_user so that it claims that
        # `@user2:host2` is in the room
        def get_users_who_share_room_with_user(user_id):
            return defer.succeed({"@user2:host2"})

        hs.get_datastore().get_users_who_share_room_with_user = (
            get_users_who_share_room_with_user
        )

        # whenever send_transaction is called, record the edu data
        self.edus = []
        self.hs.get_federation_transport_client().send_transaction.side_effect = (
            self.record_transaction
        )

    def record_transaction(self, txn, json_cb):
        data = json_cb()
        self.edus.extend(data["edus"])
        return defer.succeed({})

    def test_send_device_updates(self):
        """Basic case: each device update should result in an EDU"""
        # create a device
        u1 = self.register_user("user", "pass")
        self.login(u1, "pass", device_id="D1")

        # expect one edu
        self.assertEqual(len(self.edus), 1)
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D1", None)

        # a second call should produce no new device EDUs
        self.hs.get_federation_sender().send_device_messages("host2")
        self.pump()
        self.assertEqual(self.edus, [])

        # a second device
        self.login("user", "pass", device_id="D2")

        self.assertEqual(len(self.edus), 1)
        self.check_device_update_edu(self.edus.pop(0), u1, "D2", stream_id)

    def test_upload_signatures(self):
        """Uploading signatures on some devices should produce updates for that user"""

        e2e_handler = self.hs.get_e2e_keys_handler()

        # register two devices
        u1 = self.register_user("user", "pass")
        self.login(u1, "pass", device_id="D1")
        self.login(u1, "pass", device_id="D2")

        # expect two edus
        self.assertEqual(len(self.edus), 2)
        stream_id = None
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D1", stream_id)
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D2", stream_id)

        # upload signing keys for each device
        device1_signing_key = self.generate_and_upload_device_signing_key(u1, "D1")
        device2_signing_key = self.generate_and_upload_device_signing_key(u1, "D2")

        # expect two more edus
        self.assertEqual(len(self.edus), 2)
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D1", stream_id)
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D2", stream_id)

        # upload master key and self-signing key
        master_signing_key = generate_self_id_key()
        master_key = {
            "user_id": u1,
            "usage": ["master"],
            "keys": {key_id(master_signing_key): encode_pubkey(master_signing_key)},
        }

        # private key: HvQBbU+hc2Zr+JP1sE0XwBe1pfZZEYtJNPJLZJtS+F8
        selfsigning_signing_key = generate_self_id_key()
        selfsigning_key = {
            "user_id": u1,
            "usage": ["self_signing"],
            "keys": {
                key_id(selfsigning_signing_key): encode_pubkey(selfsigning_signing_key)
            },
        }
        sign.sign_json(selfsigning_key, u1, master_signing_key)

        cross_signing_keys = {
            "master_key": master_key,
            "self_signing_key": selfsigning_key,
        }

        self.get_success(
            e2e_handler.upload_signing_keys_for_user(u1, cross_signing_keys)
        )

        # expect signing key update edu
        self.assertEqual(len(self.edus), 1)
        self.assertEqual(self.edus.pop(0)["edu_type"], "org.matrix.signing_key_update")

        # sign the devices
        d1_json = build_device_dict(u1, "D1", device1_signing_key)
        sign.sign_json(d1_json, u1, selfsigning_signing_key)
        d2_json = build_device_dict(u1, "D2", device2_signing_key)
        sign.sign_json(d2_json, u1, selfsigning_signing_key)

        ret = self.get_success(
            e2e_handler.upload_signatures_for_device_keys(
                u1,
                {u1: {"D1": d1_json, "D2": d2_json}},
            )
        )
        self.assertEqual(ret["failures"], {})

        # expect two edus, in one or two transactions. We don't know what order the
        # devices will be updated.
        self.assertEqual(len(self.edus), 2)
        stream_id = None  # FIXME: there is a discontinuity in the stream IDs: see #7142
        for edu in self.edus:
            self.assertEqual(edu["edu_type"], "m.device_list_update")
            c = edu["content"]
            if stream_id is not None:
                self.assertEqual(c["prev_id"], [stream_id])
                self.assertGreaterEqual(c["stream_id"], stream_id)
            stream_id = c["stream_id"]
        devices = {edu["content"]["device_id"] for edu in self.edus}
        self.assertEqual({"D1", "D2"}, devices)

    def test_delete_devices(self):
        """If devices are deleted, that should result in EDUs too"""

        # create devices
        u1 = self.register_user("user", "pass")
        self.login("user", "pass", device_id="D1")
        self.login("user", "pass", device_id="D2")
        self.login("user", "pass", device_id="D3")

        # expect three edus
        self.assertEqual(len(self.edus), 3)
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D1", None)
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D2", stream_id)
        stream_id = self.check_device_update_edu(self.edus.pop(0), u1, "D3", stream_id)

        # delete them again
        self.get_success(
            self.hs.get_device_handler().delete_devices(u1, ["D1", "D2", "D3"])
        )

        # expect three edus, in an unknown order
        self.assertEqual(len(self.edus), 3)
        for edu in self.edus:
            self.assertEqual(edu["edu_type"], "m.device_list_update")
            c = edu["content"]
            self.assertGreaterEqual(
                c.items(),
                {"user_id": u1, "prev_id": [stream_id], "deleted": True}.items(),
            )
            self.assertGreaterEqual(c["stream_id"], stream_id)
            stream_id = c["stream_id"]
        devices = {edu["content"]["device_id"] for edu in self.edus}
        self.assertEqual({"D1", "D2", "D3"}, devices)

    def test_unreachable_server(self):
        """If the destination server is unreachable, all the updates should get sent on
        recovery
        """
        mock_send_txn = self.hs.get_federation_transport_client().send_transaction
        mock_send_txn.side_effect = lambda t, cb: defer.fail("fail")

        # create devices
        u1 = self.register_user("user", "pass")
        self.login("user", "pass", device_id="D1")
        self.login("user", "pass", device_id="D2")
        self.login("user", "pass", device_id="D3")

        # delete them again
        self.get_success(
            self.hs.get_device_handler().delete_devices(u1, ["D1", "D2", "D3"])
        )

        self.assertGreaterEqual(mock_send_txn.call_count, 4)

        # recover the server
        mock_send_txn.side_effect = self.record_transaction
        self.hs.get_federation_sender().send_device_messages("host2")
        self.pump()

        # for each device, there should be a single update
        self.assertEqual(len(self.edus), 3)
        stream_id = None
        for edu in self.edus:
            self.assertEqual(edu["edu_type"], "m.device_list_update")
            c = edu["content"]
            self.assertEqual(c["prev_id"], [stream_id] if stream_id is not None else [])
            if stream_id is not None:
                self.assertGreaterEqual(c["stream_id"], stream_id)
            stream_id = c["stream_id"]
        devices = {edu["content"]["device_id"] for edu in self.edus}
        self.assertEqual({"D1", "D2", "D3"}, devices)

    def test_prune_outbound_device_pokes1(self):
        """If a destination is unreachable, and the updates are pruned, we should get
        a single update.

        This case tests the behaviour when the server has never been reachable.
        """
        mock_send_txn = self.hs.get_federation_transport_client().send_transaction
        mock_send_txn.side_effect = lambda t, cb: defer.fail("fail")

        # create devices
        u1 = self.register_user("user", "pass")
        self.login("user", "pass", device_id="D1")
        self.login("user", "pass", device_id="D2")
        self.login("user", "pass", device_id="D3")

        # delete them again
        self.get_success(
            self.hs.get_device_handler().delete_devices(u1, ["D1", "D2", "D3"])
        )

        self.assertGreaterEqual(mock_send_txn.call_count, 4)

        # run the prune job
        self.reactor.advance(10)
        self.get_success(
            self.hs.get_datastore()._prune_old_outbound_device_pokes(prune_age=1)
        )

        # recover the server
        mock_send_txn.side_effect = self.record_transaction
        self.hs.get_federation_sender().send_device_messages("host2")
        self.pump()

        # there should be a single update for this user.
        self.assertEqual(len(self.edus), 1)
        edu = self.edus.pop(0)
        self.assertEqual(edu["edu_type"], "m.device_list_update")
        c = edu["content"]

        # synapse uses an empty prev_id list to indicate "needs a full resync".
        self.assertEqual(c["prev_id"], [])

    def test_prune_outbound_device_pokes2(self):
        """If a destination is unreachable, and the updates are pruned, we should get
        a single update.

        This case tests the behaviour when the server was reachable, but then goes
        offline.
        """

        # create first device
        u1 = self.register_user("user", "pass")
        self.login("user", "pass", device_id="D1")

        # expect the update EDU
        self.assertEqual(len(self.edus), 1)
        self.check_device_update_edu(self.edus.pop(0), u1, "D1", None)

        # now the server goes offline
        mock_send_txn = self.hs.get_federation_transport_client().send_transaction
        mock_send_txn.side_effect = lambda t, cb: defer.fail("fail")

        self.login("user", "pass", device_id="D2")
        self.login("user", "pass", device_id="D3")

        # delete them again
        self.get_success(
            self.hs.get_device_handler().delete_devices(u1, ["D1", "D2", "D3"])
        )

        self.assertGreaterEqual(mock_send_txn.call_count, 3)

        # run the prune job
        self.reactor.advance(10)
        self.get_success(
            self.hs.get_datastore()._prune_old_outbound_device_pokes(prune_age=1)
        )

        # recover the server
        mock_send_txn.side_effect = self.record_transaction
        self.hs.get_federation_sender().send_device_messages("host2")
        self.pump()

        # ... and we should get a single update for this user.
        self.assertEqual(len(self.edus), 1)
        edu = self.edus.pop(0)
        self.assertEqual(edu["edu_type"], "m.device_list_update")
        c = edu["content"]

        # synapse uses an empty prev_id list to indicate "needs a full resync".
        self.assertEqual(c["prev_id"], [])

    def check_device_update_edu(
        self,
        edu: JsonDict,
        user_id: str,
        device_id: str,
        prev_stream_id: Optional[int],
    ) -> int:
        """Check that the given EDU is an update for the given device
        Returns the stream_id.
        """
        self.assertEqual(edu["edu_type"], "m.device_list_update")
        content = edu["content"]

        expected = {
            "user_id": user_id,
            "device_id": device_id,
            "prev_id": [prev_stream_id] if prev_stream_id is not None else [],
        }

        self.assertLessEqual(expected.items(), content.items())
        if prev_stream_id is not None:
            self.assertGreaterEqual(content["stream_id"], prev_stream_id)
        return content["stream_id"]

    def check_signing_key_update_txn(
        self,
        txn: JsonDict,
    ) -> None:
        """Check that the txn has an EDU with a signing key update."""
        edus = txn["edus"]
        self.assertEqual(len(edus), 1)

    def generate_and_upload_device_signing_key(
        self, user_id: str, device_id: str
    ) -> SigningKey:
        """Generate a signing keypair for the given device, and upload it"""
        sk = key.generate_signing_key(device_id)

        device_dict = build_device_dict(user_id, device_id, sk)

        self.get_success(
            self.hs.get_e2e_keys_handler().upload_keys_for_user(
                user_id,
                device_id,
                {"device_keys": device_dict},
            )
        )
        return sk


def generate_self_id_key() -> SigningKey:
    """generate a signing key whose version is its public key

    ... as used by the cross-signing-keys.
    """
    k = key.generate_signing_key("x")
    k.version = encode_pubkey(k)
    return k


def key_id(k: BaseKey) -> str:
    return "%s:%s" % (k.alg, k.version)


def encode_pubkey(sk: SigningKey) -> str:
    """Encode the public key corresponding to the given signing key as base64"""
    return key.encode_verify_key_base64(key.get_verify_key(sk))


def build_device_dict(user_id: str, device_id: str, sk: SigningKey):
    """Build a dict representing the given device"""
    return {
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": [
            "m.olm.curve25519-aes-sha2",
            RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
        ],
        "keys": {
            "curve25519:" + device_id: "curve25519+key",
            key_id(sk): encode_pubkey(sk),
        },
    }
