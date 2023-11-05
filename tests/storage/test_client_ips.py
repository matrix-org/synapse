# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from typing import Any, Dict, List, Optional, Tuple, cast
from unittest.mock import AsyncMock

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.http.site import XForwardedForRequest
from synapse.rest.client import login
from synapse.server import HomeServer
from synapse.storage.databases.main.client_ips import (
    LAST_SEEN_GRANULARITY,
    DeviceLastConnectionInfo,
)
from synapse.types import UserID
from synapse.util import Clock

from tests import unittest
from tests.server import make_request
from tests.unittest import override_config


class ClientIpStoreTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def test_insert_new_client_ip(self) -> None:
        self.reactor.advance(12345678)

        user_id = "@user:id"
        device_id = "MY_DEVICE"

        # Insert a user IP
        self.get_success(
            self.store.store_device(
                user_id,
                device_id,
                "display name",
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", device_id
            )
        )

        # Trigger the storage loop
        self.reactor.advance(10)

        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, device_id)
        )

        r = result[(user_id, device_id)]
        self.assertEqual(
            DeviceLastConnectionInfo(
                user_id=user_id,
                device_id=device_id,
                ip="ip",
                user_agent="user_agent",
                last_seen=12345678000,
            ),
            r,
        )

    def test_insert_new_client_ip_none_device_id(self) -> None:
        """
        An insert with a device ID of NULL will not create a new entry, but
        update an existing entry in the user_ips table.
        """
        self.reactor.advance(12345678)

        user_id = "@user:id"

        # Add & trigger the storage loop
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", None
            )
        )
        self.reactor.advance(200)
        self.pump(0)

        result = cast(
            List[Tuple[str, str, str, Optional[str], int]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="user_ips",
                    keyvalues={"user_id": user_id},
                    retcols=[
                        "access_token",
                        "ip",
                        "user_agent",
                        "device_id",
                        "last_seen",
                    ],
                    desc="get_user_ip_and_agents",
                )
            ),
        )

        self.assertEqual(
            result, [("access_token", "ip", "user_agent", None, 12345678000)]
        )

        # Add another & trigger the storage loop
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", None
            )
        )
        self.reactor.advance(10)
        self.pump(0)

        result = cast(
            List[Tuple[str, str, str, Optional[str], int]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="user_ips",
                    keyvalues={"user_id": user_id},
                    retcols=[
                        "access_token",
                        "ip",
                        "user_agent",
                        "device_id",
                        "last_seen",
                    ],
                    desc="get_user_ip_and_agents",
                )
            ),
        )
        # Only one result, has been upserted.
        self.assertEqual(
            result, [("access_token", "ip", "user_agent", None, 12345878000)]
        )

    @parameterized.expand([(False,), (True,)])
    def test_get_last_client_ip_by_device(self, after_persisting: bool) -> None:
        """Test `get_last_client_ip_by_device` for persisted and unpersisted data"""
        self.reactor.advance(12345678)

        user_id = "@user:id"
        device_id = "MY_DEVICE"

        # Insert a user IP
        self.get_success(
            self.store.store_device(
                user_id,
                device_id,
                "display name",
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", device_id
            )
        )

        if after_persisting:
            # Trigger the storage loop
            self.reactor.advance(10)
        else:
            # Check that the new IP and user agent has not been stored yet
            db_result = cast(
                List[Tuple[str, Optional[str], Optional[str], str, Optional[int]]],
                self.get_success(
                    self.store.db_pool.simple_select_list(
                        table="devices",
                        keyvalues={},
                        retcols=(
                            "user_id",
                            "ip",
                            "user_agent",
                            "device_id",
                            "last_seen",
                        ),
                    ),
                ),
            )
            self.assertEqual(db_result, [(user_id, None, None, device_id, None)])

        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, device_id)
        )

        self.assertEqual(
            result,
            {
                (user_id, device_id): DeviceLastConnectionInfo(
                    user_id=user_id,
                    device_id=device_id,
                    ip="ip",
                    user_agent="user_agent",
                    last_seen=12345678000,
                ),
            },
        )

    def test_get_last_client_ip_by_device_combined_data(self) -> None:
        """Test that `get_last_client_ip_by_device` combines persisted and unpersisted
        data together correctly
        """
        self.reactor.advance(12345678)

        user_id = "@user:id"
        device_id_1 = "MY_DEVICE_1"
        device_id_2 = "MY_DEVICE_2"

        # Insert user IPs
        self.get_success(
            self.store.store_device(
                user_id,
                device_id_1,
                "display name",
            )
        )
        self.get_success(
            self.store.store_device(
                user_id,
                device_id_2,
                "display name",
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token_1", "ip_1", "user_agent_1", device_id_1
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token_2", "ip_2", "user_agent_2", device_id_2
            )
        )

        # Trigger the storage loop and wait for the rate limiting period to be over
        self.reactor.advance(10 + LAST_SEEN_GRANULARITY / 1000)

        # Update the user agent for the second device, without running the storage loop
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token_2", "ip_2", "user_agent_3", device_id_2
            )
        )

        # Check that the new IP and user agent has not been stored yet
        db_result = cast(
            List[Tuple[str, Optional[str], Optional[str], str, Optional[int]]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="devices",
                    keyvalues={},
                    retcols=("user_id", "ip", "user_agent", "device_id", "last_seen"),
                ),
            ),
        )
        self.assertCountEqual(
            db_result,
            [
                (user_id, "ip_1", "user_agent_1", device_id_1, 12345678000),
                (user_id, "ip_2", "user_agent_2", device_id_2, 12345678000),
            ],
        )

        # Check that data from the database and memory are combined together correctly
        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, None)
        )
        self.assertEqual(
            result,
            {
                (user_id, device_id_1): DeviceLastConnectionInfo(
                    user_id=user_id,
                    device_id=device_id_1,
                    ip="ip_1",
                    user_agent="user_agent_1",
                    last_seen=12345678000,
                ),
                (user_id, device_id_2): DeviceLastConnectionInfo(
                    user_id=user_id,
                    device_id=device_id_2,
                    ip="ip_2",
                    user_agent="user_agent_3",
                    last_seen=12345688000 + LAST_SEEN_GRANULARITY,
                ),
            },
        )

    @parameterized.expand([(False,), (True,)])
    def test_get_user_ip_and_agents(self, after_persisting: bool) -> None:
        """Test `get_user_ip_and_agents` for persisted and unpersisted data"""
        self.reactor.advance(12345678)

        user_id = "@user:id"
        user = UserID.from_string(user_id)

        # Insert a user IP
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "MY_DEVICE"
            )
        )

        if after_persisting:
            # Trigger the storage loop
            self.reactor.advance(10)
        else:
            # Check that the new IP and user agent has not been stored yet
            db_result = self.get_success(
                self.store.db_pool.simple_select_list(
                    table="user_ips",
                    keyvalues={},
                    retcols=("access_token", "ip", "user_agent", "last_seen"),
                ),
            )
            self.assertEqual(db_result, [])

        self.assertEqual(
            self.get_success(self.store.get_user_ip_and_agents(user)),
            [
                {
                    "access_token": "access_token",
                    "ip": "ip",
                    "user_agent": "user_agent",
                    "last_seen": 12345678000,
                },
            ],
        )

    def test_get_user_ip_and_agents_combined_data(self) -> None:
        """Test that `get_user_ip_and_agents` combines persisted and unpersisted data
        together correctly
        """
        self.reactor.advance(12345678)

        user_id = "@user:id"
        user = UserID.from_string(user_id)

        # Insert user IPs
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip_1", "user_agent_1", "MY_DEVICE_1"
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip_2", "user_agent_2", "MY_DEVICE_2"
            )
        )

        # Trigger the storage loop and wait for the rate limiting period to be over
        self.reactor.advance(10 + LAST_SEEN_GRANULARITY / 1000)

        # Update the user agent for the second device, without running the storage loop
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip_2", "user_agent_3", "MY_DEVICE_2"
            )
        )

        # Check that the new IP and user agent has not been stored yet
        db_result = cast(
            List[Tuple[str, str, str, int]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="user_ips",
                    keyvalues={},
                    retcols=("access_token", "ip", "user_agent", "last_seen"),
                ),
            ),
        )
        self.assertEqual(
            db_result,
            [
                ("access_token", "ip_1", "user_agent_1", 12345678000),
                ("access_token", "ip_2", "user_agent_2", 12345678000),
            ],
        )

        # Check that data from the database and memory are combined together correctly
        self.assertCountEqual(
            self.get_success(self.store.get_user_ip_and_agents(user)),
            [
                {
                    "access_token": "access_token",
                    "ip": "ip_1",
                    "user_agent": "user_agent_1",
                    "last_seen": 12345678000,
                },
                {
                    "access_token": "access_token",
                    "ip": "ip_2",
                    "user_agent": "user_agent_3",
                    "last_seen": 12345688000 + LAST_SEEN_GRANULARITY,
                },
            ],
        )

    @override_config({"limit_usage_by_mau": False, "max_mau_value": 50})
    def test_disabled_monthly_active_user(self) -> None:
        user_id = "@user:server"
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

    @override_config({"limit_usage_by_mau": True, "max_mau_value": 50})
    def test_adding_monthly_active_user_when_full(self) -> None:
        lots_of_users = 100
        user_id = "@user:server"

        self.store.get_monthly_active_count = AsyncMock(return_value=lots_of_users)
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

    @override_config({"limit_usage_by_mau": True, "max_mau_value": 50})
    def test_adding_monthly_active_user_when_space(self) -> None:
        user_id = "@user:server"
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

        # Trigger the saving loop
        self.reactor.advance(10)

        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertTrue(active)

    @override_config({"limit_usage_by_mau": True, "max_mau_value": 50})
    def test_updating_monthly_active_user_when_space(self) -> None:
        user_id = "@user:server"
        self.get_success(self.store.register_user(user_id=user_id, password_hash=None))

        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

        # Trigger the saving loop
        self.reactor.advance(10)

        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertTrue(active)

    def test_devices_last_seen_bg_update(self) -> None:
        # First make sure we have completed all updates.
        self.wait_for_background_updates()

        user_id = "@user:id"
        device_id = "MY_DEVICE"

        # Insert a user IP
        self.get_success(
            self.store.store_device(
                user_id,
                device_id,
                "display name",
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", device_id
            )
        )
        # Force persisting to disk
        self.reactor.advance(200)

        # But clear the associated entry in devices table
        self.get_success(
            self.store.db_pool.simple_update(
                table="devices",
                keyvalues={"user_id": user_id, "device_id": device_id},
                updatevalues={"last_seen": None, "ip": None, "user_agent": None},
                desc="test_devices_last_seen_bg_update",
            )
        )

        # We should now get nulls when querying
        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, device_id)
        )

        r = result[(user_id, device_id)]
        self.assertEqual(
            DeviceLastConnectionInfo(
                user_id=user_id,
                device_id=device_id,
                ip=None,
                user_agent=None,
                last_seen=None,
            ),
            r,
        )

        # Register the background update to run again.
        self.get_success(
            self.store.db_pool.simple_insert(
                table="background_updates",
                values={
                    "update_name": "devices_last_seen",
                    "progress_json": "{}",
                    "depends_on": None,
                },
            )
        )

        # ... and tell the DataStore that it hasn't finished all updates yet
        self.store.db_pool.updates._all_done = False

        # Now let's actually drive the updates to completion
        self.wait_for_background_updates()

        # We should now get the correct result again
        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, device_id)
        )

        r = result[(user_id, device_id)]
        self.assertEqual(
            DeviceLastConnectionInfo(
                user_id=user_id,
                device_id=device_id,
                ip="ip",
                user_agent="user_agent",
                last_seen=0,
            ),
            r,
        )

    def test_old_user_ips_pruned(self) -> None:
        # First make sure we have completed all updates.
        self.wait_for_background_updates()

        user_id = "@user:id"
        device_id = "MY_DEVICE"

        # Insert a user IP
        self.get_success(
            self.store.store_device(
                user_id,
                device_id,
                "display name",
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", device_id
            )
        )

        # Force persisting to disk
        self.reactor.advance(200)

        # We should see that in the DB
        result = cast(
            List[Tuple[str, str, str, Optional[str], int]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="user_ips",
                    keyvalues={"user_id": user_id},
                    retcols=[
                        "access_token",
                        "ip",
                        "user_agent",
                        "device_id",
                        "last_seen",
                    ],
                    desc="get_user_ip_and_agents",
                )
            ),
        )

        self.assertEqual(
            result,
            [("access_token", "ip", "user_agent", device_id, 0)],
        )

        # Now advance by a couple of months
        self.reactor.advance(60 * 24 * 60 * 60)

        # We should get no results.
        result = cast(
            List[Tuple[str, str, str, Optional[str], int]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="user_ips",
                    keyvalues={"user_id": user_id},
                    retcols=[
                        "access_token",
                        "ip",
                        "user_agent",
                        "device_id",
                        "last_seen",
                    ],
                    desc="get_user_ip_and_agents",
                )
            ),
        )

        self.assertEqual(result, [])

        # But we should still get the correct values for the device
        result2 = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, device_id)
        )

        r = result2[(user_id, device_id)]
        self.assertEqual(
            DeviceLastConnectionInfo(
                user_id=user_id,
                device_id=device_id,
                ip="ip",
                user_agent="user_agent",
                last_seen=0,
            ),
            r,
        )

    def test_invalid_user_agents_are_ignored(self) -> None:
        # First make sure we have completed all updates.
        self.wait_for_background_updates()

        user_id1 = "@user1:id"
        user_id2 = "@user2:id"
        device_id1 = "MY_DEVICE1"
        device_id2 = "MY_DEVICE2"
        access_token1 = "access_token1"
        access_token2 = "access_token2"

        # Insert a user IP 1
        self.get_success(
            self.store.store_device(
                user_id1,
                device_id1,
                "display name1",
            )
        )
        # Insert a user IP 2
        self.get_success(
            self.store.store_device(
                user_id2,
                device_id2,
                "display name2",
            )
        )

        self.get_success(
            self.store.insert_client_ip(
                user_id1, access_token1, "ip", "sync-v3-proxy-", device_id1
            )
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id2, access_token2, "ip", "user_agent", device_id2
            )
        )
        # Force persisting to disk
        self.reactor.advance(200)

        # We should see that in the DB
        result = cast(
            List[Tuple[str, str, str, Optional[str], int]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="user_ips",
                    keyvalues={},
                    retcols=[
                        "access_token",
                        "ip",
                        "user_agent",
                        "device_id",
                        "last_seen",
                    ],
                    desc="get_user_ip_and_agents",
                )
            ),
        )

        # ensure user1 is filtered out
        self.assertEqual(result, [(access_token2, "ip", "user_agent", device_id2, 0)])


class ClientIpAuthTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = self.hs.get_datastores().main
        self.user_id = self.register_user("bob", "abc123", True)

    def test_request_with_xforwarded(self) -> None:
        """
        The IP in X-Forwarded-For is entered into the client IPs table.
        """
        self._runtest(
            {b"X-Forwarded-For": b"127.9.0.1"},
            "127.9.0.1",
            {"request": XForwardedForRequest},
        )

    def test_request_from_getPeer(self) -> None:
        """
        The IP returned by getPeer is entered into the client IPs table, if
        there's no X-Forwarded-For header.
        """
        self._runtest({}, "127.0.0.1", {})

    def _runtest(
        self,
        headers: Dict[bytes, bytes],
        expected_ip: str,
        make_request_args: Dict[str, Any],
    ) -> None:
        device_id = "bleb"

        access_token = self.login("bob", "abc123", device_id=device_id)

        # Advance to a known time
        self.reactor.advance(123456 - self.reactor.seconds())

        headers1 = {b"User-Agent": b"Mozzila pizza"}
        headers1.update(headers)

        make_request(
            self.reactor,
            self.site,
            "GET",
            "/_synapse/admin/v2/users/" + self.user_id,
            access_token=access_token,
            custom_headers=headers1.items(),
            **make_request_args,
        )

        # Advance so the save loop occurs
        self.reactor.advance(100)

        result = self.get_success(
            self.store.get_last_client_ip_by_device(self.user_id, device_id)
        )
        r = result[(self.user_id, device_id)]
        self.assertEqual(
            DeviceLastConnectionInfo(
                user_id=self.user_id,
                device_id=device_id,
                ip=expected_ip,
                user_agent="Mozzila pizza",
                last_seen=123456100,
            ),
            r,
        )
