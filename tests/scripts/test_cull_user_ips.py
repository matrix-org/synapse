# -*- coding: utf-8 -*-
# Copyright 2018 New Vector
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

from synapse._scripts.cull_user_ips import _main
from synapse.rest.client.v1 import admin, login

from tests.unittest import HomeserverTestCase


class CullIPTests(HomeserverTestCase):

    servlets = [admin.register_servlets, login.register_servlets]

    def test_invalid_tokens(self):

        logs = []

        storage = self.hs.get_datastore()

        u1 = self.register_user("user1", "a")
        u1_login = self.login(u1, "a")
        u1_devices = list(self.get_success(storage.get_devices_by_user(u1)).keys())

        u2 = self.register_user("user2", "a")
        u2_login = self.login(u2, "a")
        u2_devices = list(self.get_success(storage.get_devices_by_user(u2)).keys())

        # Add some user IPs
        storage.insert_client_ip(u1, u1_login, "1", "a", u1_devices[0], 12345)
        storage.insert_client_ip(u1, u1_login, "2", "b", u1_devices[0], 12346)
        storage.insert_client_ip(u1, "OLDTOKEN", "3", "c", u1_devices[0], 12347)

        storage.insert_client_ip(u2, u2_login, "4", "a", u2_devices[0], 12345)

        storage._update_client_ips_batch()
        self.pump(1)

        u1_entries = self.get_success(
            storage._simple_select_list(
                table="user_ips",
                keyvalues={"user_id": u1},
                retcols=["access_token", "ip", "user_agent", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )

        u2_entries = self.get_success(
            storage._simple_select_list(
                table="user_ips",
                keyvalues={"user_id": u2},
                retcols=["access_token", "ip", "user_agent", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )

        self.assertEqual(len(u1_entries), 3)
        self.assertEqual(len(u2_entries), 1)

        conn = self.hs.get_db_conn(False)

        _main(conn, storage.database_engine, _print=logs.append)

        u1_entries = self.get_success(
            storage._simple_select_list(
                table="user_ips",
                keyvalues={"user_id": u1},
                retcols=["access_token", "ip", "user_agent", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )

        u2_entries = self.get_success(
            storage._simple_select_list(
                table="user_ips",
                keyvalues={"user_id": u2},
                retcols=["access_token", "ip", "user_agent", "last_seen"],
                desc="get_user_ip_and_agents",
            )
        )

        # We deleted the invalid access token for u1, and all entries with it,
        # as well as one outdated entry for a valid access token. We did not
        # touch any of u2's rows.
        self.assertEqual(len(u1_entries), 1)
        self.assertEqual(len(u2_entries), 1)

        self.assertEqual(u1_entries[0]["last_seen"], 12346)
        self.assertEqual(u1_entries[0]["user_agent"], "b")
