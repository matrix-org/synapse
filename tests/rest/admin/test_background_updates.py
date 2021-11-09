# Copyright 2021 The Matrix.org Foundation C.I.C.
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

import synapse.rest.admin
from synapse.rest.client import login
from synapse.server import HomeServer

from tests import unittest


class BackgroundUpdatesTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs: HomeServer):
        self.store = hs.get_datastore()
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

    def _register_bg_update(self):
        "Adds a bg update but doesn't start it"

        async def _fake_update(progress, batch_size) -> int:
            await self.clock.sleep(0.2)
            return batch_size

        self.store.db_pool.updates.register_background_update_handler(
            "test_update",
            _fake_update,
        )

        self.get_success(
            self.store.db_pool.simple_insert(
                table="background_updates",
                values={
                    "update_name": "test_update",
                    "progress_json": "{}",
                },
            )
        )

    def test_status_empty(self):
        """Test the status API works."""

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/background_updates/status",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Background updates should be enabled, but none should be running.
        self.assertDictEqual(
            channel.json_body, {"current_updates": {}, "enabled": True}
        )

    def test_status_bg_update(self):
        """Test the status API works with a background update."""

        # Create a new background update

        self._register_bg_update()

        self.store.db_pool.updates.start_doing_background_updates()
        self.reactor.pump([1.0, 1.0])

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/background_updates/status",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Background updates should be enabled, and one should be running.
        self.assertDictEqual(
            channel.json_body,
            {
                "current_updates": {
                    "master": {
                        "name": "test_update",
                        "average_items_per_ms": 0.1,
                        "total_duration_ms": 1000.0,
                        "total_item_count": 100,
                    }
                },
                "enabled": True,
            },
        )

    def test_enabled(self):
        """Test the enabled API works."""

        # Create a new background update

        self._register_bg_update()
        self.store.db_pool.updates.start_doing_background_updates()

        # Test that GET works and returns enabled is True.
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/background_updates/enabled",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertDictEqual(channel.json_body, {"enabled": True})

        # Disable the BG updates
        channel = self.make_request(
            "POST",
            "/_synapse/admin/v1/background_updates/enabled",
            content={"enabled": False},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertDictEqual(channel.json_body, {"enabled": False})

        # Advance a bit and get the current status, note this will finish the in
        # flight background update so we call it the status API twice and check
        # there was no change.
        self.reactor.pump([1.0, 1.0])

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/background_updates/status",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertDictEqual(
            channel.json_body,
            {
                "current_updates": {
                    "master": {
                        "name": "test_update",
                        "average_items_per_ms": 0.1,
                        "total_duration_ms": 1000.0,
                        "total_item_count": 100,
                    }
                },
                "enabled": False,
            },
        )

        # Run the reactor for a bit so the BG updates would have a chance to run
        # if they were to.
        self.reactor.pump([1.0, 1.0])

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/background_updates/status",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # There should be no change from the previous /status response.
        self.assertDictEqual(
            channel.json_body,
            {
                "current_updates": {
                    "master": {
                        "name": "test_update",
                        "average_items_per_ms": 0.1,
                        "total_duration_ms": 1000.0,
                        "total_item_count": 100,
                    }
                },
                "enabled": False,
            },
        )

        # Re-enable the background updates.

        channel = self.make_request(
            "POST",
            "/_synapse/admin/v1/background_updates/enabled",
            content={"enabled": True},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        self.assertDictEqual(channel.json_body, {"enabled": True})

        self.reactor.pump([1.0, 1.0])

        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/background_updates/status",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Background updates should be enabled and making progress.
        self.assertDictEqual(
            channel.json_body,
            {
                "current_updates": {
                    "master": {
                        "name": "test_update",
                        "average_items_per_ms": 0.1,
                        "total_duration_ms": 2000.0,
                        "total_item_count": 200,
                    }
                },
                "enabled": True,
            },
        )
