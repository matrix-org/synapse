# -*- coding: utf-8 -*-
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

from mock import Mock

from twisted.internet import defer

import synapse.rest.admin
from synapse.http.site import XForwardedForRequest
from synapse.rest.client.v1 import login

from tests import unittest
from tests.unittest import override_config


class ClientIpStoreTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()
        return hs

    def prepare(self, hs, reactor, clock):
        self.store = self.hs.get_datastore()

    def test_insert_new_client_ip(self):
        self.reactor.advance(12345678)

        user_id = "@user:id"
        device_id = "MY_DEVICE"

        # Insert a user IP
        self.get_success(self.store.store_device(user_id, device_id, "display name",))
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
        self.assertDictContainsSubset(
            {
                "user_id": user_id,
                "device_id": device_id,
                "ip": "ip",
                "user_agent": "user_agent",
                "last_seen": 12345678000,
            },
            r,
        )

    def test_insert_new_client_ip_none_device_id(self):
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

        result = self.get_success(
            self.store.db.simple_select_list(
                table="user_ips",
                keyvalues={"user_id": user_id},
                retcols=["access_token", "ip", "user_agent", "device_id", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )

        self.assertEqual(
            result,
            [
                {
                    "access_token": "access_token",
                    "ip": "ip",
                    "user_agent": "user_agent",
                    "device_id": None,
                    "last_seen": 12345678000,
                }
            ],
        )

        # Add another & trigger the storage loop
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", None
            )
        )
        self.reactor.advance(10)
        self.pump(0)

        result = self.get_success(
            self.store.db.simple_select_list(
                table="user_ips",
                keyvalues={"user_id": user_id},
                retcols=["access_token", "ip", "user_agent", "device_id", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )
        # Only one result, has been upserted.
        self.assertEqual(
            result,
            [
                {
                    "access_token": "access_token",
                    "ip": "ip",
                    "user_agent": "user_agent",
                    "device_id": None,
                    "last_seen": 12345878000,
                }
            ],
        )

    @override_config({"limit_usage_by_mau": False, "max_mau_value": 50})
    def test_disabled_monthly_active_user(self):
        user_id = "@user:server"
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

    @override_config({"limit_usage_by_mau": True, "max_mau_value": 50})
    def test_adding_monthly_active_user_when_full(self):
        lots_of_users = 100
        user_id = "@user:server"

        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(lots_of_users)
        )
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", "device_id"
            )
        )
        active = self.get_success(self.store.user_last_seen_monthly_active(user_id))
        self.assertFalse(active)

    @override_config({"limit_usage_by_mau": True, "max_mau_value": 50})
    def test_adding_monthly_active_user_when_space(self):
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
    def test_updating_monthly_active_user_when_space(self):
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

    def test_devices_last_seen_bg_update(self):
        # First make sure we have completed all updates.
        while not self.get_success(
            self.store.db.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db.updates.do_next_background_update(100), by=0.1
            )

        user_id = "@user:id"
        device_id = "MY_DEVICE"

        # Insert a user IP
        self.get_success(self.store.store_device(user_id, device_id, "display name",))
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", device_id
            )
        )
        # Force persisting to disk
        self.reactor.advance(200)

        # But clear the associated entry in devices table
        self.get_success(
            self.store.db.simple_update(
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
        self.assertDictContainsSubset(
            {
                "user_id": user_id,
                "device_id": device_id,
                "ip": None,
                "user_agent": None,
                "last_seen": None,
            },
            r,
        )

        # Register the background update to run again.
        self.get_success(
            self.store.db.simple_insert(
                table="background_updates",
                values={
                    "update_name": "devices_last_seen",
                    "progress_json": "{}",
                    "depends_on": None,
                },
            )
        )

        # ... and tell the DataStore that it hasn't finished all updates yet
        self.store.db.updates._all_done = False

        # Now let's actually drive the updates to completion
        while not self.get_success(
            self.store.db.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db.updates.do_next_background_update(100), by=0.1
            )

        # We should now get the correct result again
        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, device_id)
        )

        r = result[(user_id, device_id)]
        self.assertDictContainsSubset(
            {
                "user_id": user_id,
                "device_id": device_id,
                "ip": "ip",
                "user_agent": "user_agent",
                "last_seen": 0,
            },
            r,
        )

    def test_old_user_ips_pruned(self):
        # First make sure we have completed all updates.
        while not self.get_success(
            self.store.db.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db.updates.do_next_background_update(100), by=0.1
            )

        user_id = "@user:id"
        device_id = "MY_DEVICE"

        # Insert a user IP
        self.get_success(self.store.store_device(user_id, device_id, "display name",))
        self.get_success(
            self.store.insert_client_ip(
                user_id, "access_token", "ip", "user_agent", device_id
            )
        )

        # Force persisting to disk
        self.reactor.advance(200)

        # We should see that in the DB
        result = self.get_success(
            self.store.db.simple_select_list(
                table="user_ips",
                keyvalues={"user_id": user_id},
                retcols=["access_token", "ip", "user_agent", "device_id", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )

        self.assertEqual(
            result,
            [
                {
                    "access_token": "access_token",
                    "ip": "ip",
                    "user_agent": "user_agent",
                    "device_id": device_id,
                    "last_seen": 0,
                }
            ],
        )

        # Now advance by a couple of months
        self.reactor.advance(60 * 24 * 60 * 60)

        # We should get no results.
        result = self.get_success(
            self.store.db.simple_select_list(
                table="user_ips",
                keyvalues={"user_id": user_id},
                retcols=["access_token", "ip", "user_agent", "device_id", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )

        self.assertEqual(result, [])

        # But we should still get the correct values for the device
        result = self.get_success(
            self.store.get_last_client_ip_by_device(user_id, device_id)
        )

        r = result[(user_id, device_id)]
        self.assertDictContainsSubset(
            {
                "user_id": user_id,
                "device_id": device_id,
                "ip": "ip",
                "user_agent": "user_agent",
                "last_seen": 0,
            },
            r,
        )


class ClientIpAuthTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()
        return hs

    def prepare(self, hs, reactor, clock):
        self.store = self.hs.get_datastore()
        self.user_id = self.register_user("bob", "abc123", True)

    def test_request_with_xforwarded(self):
        """
        The IP in X-Forwarded-For is entered into the client IPs table.
        """
        self._runtest(
            {b"X-Forwarded-For": b"127.9.0.1"},
            "127.9.0.1",
            {"request": XForwardedForRequest},
        )

    def test_request_from_getPeer(self):
        """
        The IP returned by getPeer is entered into the client IPs table, if
        there's no X-Forwarded-For header.
        """
        self._runtest({}, "127.0.0.1", {})

    def _runtest(self, headers, expected_ip, make_request_args):
        device_id = "bleb"

        access_token = self.login("bob", "abc123", device_id=device_id)

        # Advance to a known time
        self.reactor.advance(123456 - self.reactor.seconds())

        request, channel = self.make_request(
            "GET",
            "/_matrix/client/r0/admin/users/" + self.user_id,
            access_token=access_token,
            **make_request_args
        )
        request.requestHeaders.addRawHeader(b"User-Agent", b"Mozzila pizza")

        # Add the optional headers
        for h, v in headers.items():
            request.requestHeaders.addRawHeader(h, v)
        self.render(request)

        # Advance so the save loop occurs
        self.reactor.advance(100)

        result = self.get_success(
            self.store.get_last_client_ip_by_device(self.user_id, device_id)
        )
        r = result[(self.user_id, device_id)]
        self.assertDictContainsSubset(
            {
                "user_id": self.user_id,
                "device_id": device_id,
                "ip": expected_ip,
                "user_agent": "Mozzila pizza",
                "last_seen": 123456100,
            },
            r,
        )
