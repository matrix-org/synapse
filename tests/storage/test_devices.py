# Copyright 2016-2021 The Matrix.org Foundation C.I.C.
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

import synapse.api.errors
from synapse.api.constants import EduTypes

from tests.unittest import HomeserverTestCase


class DeviceStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastores().main

    def add_device_change(self, user_id, device_ids, host):
        """Add a device list change for the given device to
        `device_lists_outbound_pokes` table.
        """

        for device_id in device_ids:
            stream_id = self.get_success(
                self.store.add_device_change_to_streams(
                    user_id, [device_id], ["!some:room"]
                )
            )

            self.get_success(
                self.store.add_device_list_outbound_pokes(
                    user_id=user_id,
                    device_id=device_id,
                    room_id="!some:room",
                    stream_id=stream_id,
                    hosts=[host],
                    context={},
                )
            )

    def test_store_new_device(self):
        self.get_success(
            self.store.store_device("user_id", "device_id", "display_name")
        )

        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertDictContainsSubset(
            {
                "user_id": "user_id",
                "device_id": "device_id",
                "display_name": "display_name",
            },
            res,
        )

    def test_get_devices_by_user(self):
        self.get_success(
            self.store.store_device("user_id", "device1", "display_name 1")
        )
        self.get_success(
            self.store.store_device("user_id", "device2", "display_name 2")
        )
        self.get_success(
            self.store.store_device("user_id2", "device3", "display_name 3")
        )

        res = self.get_success(self.store.get_devices_by_user("user_id"))
        self.assertEqual(2, len(res.keys()))
        self.assertDictContainsSubset(
            {
                "user_id": "user_id",
                "device_id": "device1",
                "display_name": "display_name 1",
            },
            res["device1"],
        )
        self.assertDictContainsSubset(
            {
                "user_id": "user_id",
                "device_id": "device2",
                "display_name": "display_name 2",
            },
            res["device2"],
        )

    def test_count_devices_by_users(self):
        self.get_success(
            self.store.store_device("user_id", "device1", "display_name 1")
        )
        self.get_success(
            self.store.store_device("user_id", "device2", "display_name 2")
        )
        self.get_success(
            self.store.store_device("user_id2", "device3", "display_name 3")
        )

        res = self.get_success(self.store.count_devices_by_users())
        self.assertEqual(0, res)

        res = self.get_success(self.store.count_devices_by_users(["unknown"]))
        self.assertEqual(0, res)

        res = self.get_success(self.store.count_devices_by_users(["user_id"]))
        self.assertEqual(2, res)

        res = self.get_success(
            self.store.count_devices_by_users(["user_id", "user_id2"])
        )
        self.assertEqual(3, res)

    def test_get_device_updates_by_remote(self):
        device_ids = ["device_id1", "device_id2"]

        # Add two device updates with sequential `stream_id`s
        self.add_device_change("@user_id:test", device_ids, "somehost")

        # Get all device updates ever meant for this remote
        now_stream_id, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", -1, limit=100)
        )

        # Check original device_ids are contained within these updates
        self._check_devices_in_updates(device_ids, device_updates)

    def test_get_device_updates_by_remote_can_limit_properly(self):
        """
        Tests that `get_device_updates_by_remote` returns an appropriate
        stream_id to resume fetching from (without skipping any results).
        """

        # Add some device updates with sequential `stream_id`s
        device_ids = [
            "device_id1",
            "device_id2",
            "device_id3",
            "device_id4",
            "device_id5",
        ]
        self.add_device_change("@user_id:test", device_ids, "somehost")

        # Get device updates meant for this remote
        next_stream_id, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", -1, limit=3)
        )

        # Check the first three original device_ids are contained within these updates
        self._check_devices_in_updates(device_ids[:3], device_updates)

        # Get the next batch of device updates
        next_stream_id, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", next_stream_id, limit=3)
        )

        # Check the last two original device_ids are contained within these updates
        self._check_devices_in_updates(device_ids[3:], device_updates)

        # Add some more device updates to ensure it still resumes properly
        device_ids = ["device_id6", "device_id7"]
        self.add_device_change("@user_id:test", device_ids, "somehost")

        # Get the next batch of device updates
        next_stream_id, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", next_stream_id, limit=3)
        )

        # Check the newly-added device_ids are contained within these updates
        self._check_devices_in_updates(device_ids, device_updates)

        # Check there are no more device updates left.
        _, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", next_stream_id, limit=3)
        )
        self.assertEqual(device_updates, [])

    def test_get_device_updates_by_remote_cross_signing_key_updates(
        self,
    ) -> None:
        """
        Tests that `get_device_updates_by_remote` limits the length of the return value
        properly when cross-signing key updates are present.
        Current behaviour is that the cross-signing key updates will always come in pairs,
        even if that means leaving an earlier batch one EDU short of the limit.
        """

        assert self.hs.is_mine_id(
            "@user_id:test"
        ), "Test not valid: this MXID should be considered local"

        self.get_success(
            self.store.set_e2e_cross_signing_key(
                "@user_id:test",
                "master",
                {
                    "keys": {
                        "ed25519:fakeMaster": "aaafakefakefake1AAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    },
                    "signatures": {
                        "@user_id:test": {
                            "ed25519:fake2": "aaafakefakefake2AAAAAAAAAAAAAAAAAAAAAAAAAAA="
                        }
                    },
                },
            )
        )
        self.get_success(
            self.store.set_e2e_cross_signing_key(
                "@user_id:test",
                "self_signing",
                {
                    "keys": {
                        "ed25519:fakeSelfSigning": "aaafakefakefake3AAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    },
                    "signatures": {
                        "@user_id:test": {
                            "ed25519:fake4": "aaafakefakefake4AAAAAAAAAAAAAAAAAAAAAAAAAAA="
                        }
                    },
                },
            )
        )

        # Add some device updates with sequential `stream_id`s
        # Note that the public cross-signing keys occupy the same space as device IDs,
        # so also notify that those have updated.
        device_ids = [
            "device_id1",
            "device_id2",
            "fakeMaster",
            "fakeSelfSigning",
        ]

        self.add_device_change("@user_id:test", device_ids, "somehost")

        # Get device updates meant for this remote
        next_stream_id, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", -1, limit=3)
        )

        # Here we expect the device updates for `device_id1` and `device_id2`.
        # That means we only receive 2 updates this time around.
        # If we had a higher limit, we would expect to see the pair of
        # (unstable-prefixed & unprefixed) signing key updates for the device
        # represented by `fakeMaster` and `fakeSelfSigning`.
        # Our implementation only sends these two variants together, so we get
        # a short batch.
        self.assertEqual(len(device_updates), 2, device_updates)

        # Check the first two devices (device_id1, device_id2) came out.
        self._check_devices_in_updates(device_ids[:2], device_updates)

        # Get more device updates meant for this remote
        next_stream_id, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", next_stream_id, limit=3)
        )

        # The next 2 updates should be a cross-signing key update
        # (the master key update and the self-signing key update are combined into
        # one 'signing key update', but the cross-signing key update is emitted
        # twice, once with an unprefixed type and once again with an unstable-prefixed type)
        # (This is a temporary arrangement for backwards compatibility!)
        self.assertEqual(len(device_updates), 2, device_updates)
        self.assertEqual(
            device_updates[0][0], EduTypes.SIGNING_KEY_UPDATE, device_updates[0]
        )
        self.assertEqual(
            device_updates[1][0],
            EduTypes.UNSTABLE_SIGNING_KEY_UPDATE,
            device_updates[1],
        )

        # Check there are no more device updates left.
        _, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", next_stream_id, limit=3)
        )
        self.assertEqual(device_updates, [])

    def _check_devices_in_updates(self, expected_device_ids, device_updates):
        """Check that an specific device ids exist in a list of device update EDUs"""
        self.assertEqual(len(device_updates), len(expected_device_ids))

        received_device_ids = {
            update["device_id"] for edu_type, update in device_updates
        }
        self.assertEqual(received_device_ids, set(expected_device_ids))

    def test_update_device(self):
        self.get_success(
            self.store.store_device("user_id", "device_id", "display_name 1")
        )

        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertEqual("display_name 1", res["display_name"])

        # do a no-op first
        self.get_success(self.store.update_device("user_id", "device_id"))
        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertEqual("display_name 1", res["display_name"])

        # do the update
        self.get_success(
            self.store.update_device(
                "user_id", "device_id", new_display_name="display_name 2"
            )
        )

        # check it worked
        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertEqual("display_name 2", res["display_name"])

    def test_update_unknown_device(self):
        exc = self.get_failure(
            self.store.update_device(
                "user_id", "unknown_device_id", new_display_name="display_name 2"
            ),
            synapse.api.errors.StoreError,
        )
        self.assertEqual(404, exc.value.code)
