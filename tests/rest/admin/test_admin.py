# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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

import urllib.parse
from typing import Dict

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

import synapse.rest.admin
from synapse.http.server import JsonResource
from synapse.rest.admin import VersionServlet
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.test_utils import SMALL_PNG


class VersionTestCase(unittest.HomeserverTestCase):
    url = "/_synapse/admin/v1/server_version"

    def create_test_resource(self) -> JsonResource:
        resource = JsonResource(self.hs)
        VersionServlet(self.hs).register(resource)
        return resource

    def test_version_string(self) -> None:
        channel = self.make_request("GET", self.url, shorthand=False)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual({"server_version"}, set(channel.json_body.keys()))


class QuarantineMediaTestCase(unittest.HomeserverTestCase):
    """Test /quarantine_media admin API."""

    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.admin.register_servlets_for_media_repo,
        login.register_servlets,
        room.register_servlets,
    ]

    def create_resource_dict(self) -> Dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def _ensure_quarantined(
        self, admin_user_tok: str, server_and_media_id: str
    ) -> None:
        """Ensure a piece of media is quarantined when trying to access it."""
        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/{server_and_media_id}",
            shorthand=False,
            access_token=admin_user_tok,
        )

        # Should be quarantined
        self.assertEqual(
            404,
            channel.code,
            msg=(
                "Expected to receive a 404 on accessing quarantined media: %s"
                % server_and_media_id
            ),
        )

    @parameterized.expand(
        [
            # Attempt quarantine media APIs as non-admin
            "/_synapse/admin/v1/media/quarantine/example.org/abcde12345",
            # And the roomID/userID endpoint
            "/_synapse/admin/v1/room/!room%3Aexample.com/media/quarantine",
        ]
    )
    def test_quarantine_media_requires_admin(self, url: str) -> None:
        self.register_user("nonadmin", "pass", admin=False)
        non_admin_user_tok = self.login("nonadmin", "pass")

        channel = self.make_request(
            "POST",
            url.encode("ascii"),
            access_token=non_admin_user_tok,
        )

        # Expect a forbidden error
        self.assertEqual(
            403,
            channel.code,
            msg="Expected forbidden on quarantining media as a non-admin",
        )

    def test_quarantine_media_by_id(self) -> None:
        self.register_user("id_admin", "pass", admin=True)
        admin_user_tok = self.login("id_admin", "pass")

        self.register_user("id_nonadmin", "pass", admin=False)
        non_admin_user_tok = self.login("id_nonadmin", "pass")

        # Upload some media into the room
        response = self.helper.upload_media(SMALL_PNG, tok=admin_user_tok)

        # Extract media ID from the response
        server_name_and_media_id = response["content_uri"][6:]  # Cut off 'mxc://'
        server_name, media_id = server_name_and_media_id.split("/")

        # Attempt to access the media
        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/{server_name_and_media_id}",
            shorthand=False,
            access_token=non_admin_user_tok,
        )

        # Should be successful
        self.assertEqual(200, channel.code)

        # Quarantine the media
        url = "/_synapse/admin/v1/media/quarantine/%s/%s" % (
            urllib.parse.quote(server_name),
            urllib.parse.quote(media_id),
        )
        channel = self.make_request(
            "POST",
            url,
            access_token=admin_user_tok,
        )
        self.pump(1.0)
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Attempt to access the media
        self._ensure_quarantined(admin_user_tok, server_name_and_media_id)

    @parameterized.expand(
        [
            # regular API path
            "/_synapse/admin/v1/room/%s/media/quarantine",
            # deprecated API path
            "/_synapse/admin/v1/quarantine_media/%s",
        ]
    )
    def test_quarantine_all_media_in_room(self, url: str) -> None:
        self.register_user("room_admin", "pass", admin=True)
        admin_user_tok = self.login("room_admin", "pass")

        non_admin_user = self.register_user("room_nonadmin", "pass", admin=False)
        non_admin_user_tok = self.login("room_nonadmin", "pass")

        room_id = self.helper.create_room_as(non_admin_user, tok=admin_user_tok)
        self.helper.join(room_id, non_admin_user, tok=non_admin_user_tok)

        # Upload some media
        response_1 = self.helper.upload_media(SMALL_PNG, tok=non_admin_user_tok)
        response_2 = self.helper.upload_media(SMALL_PNG, tok=non_admin_user_tok)

        # Extract mxcs
        mxc_1 = response_1["content_uri"]
        mxc_2 = response_2["content_uri"]

        # Send it into the room
        self.helper.send_event(
            room_id,
            "m.room.message",
            content={"body": "image-1", "msgtype": "m.image", "url": mxc_1},
            txn_id="111",
            tok=non_admin_user_tok,
        )
        self.helper.send_event(
            room_id,
            "m.room.message",
            content={"body": "image-2", "msgtype": "m.image", "url": mxc_2},
            txn_id="222",
            tok=non_admin_user_tok,
        )

        channel = self.make_request(
            "POST",
            url % urllib.parse.quote(room_id),
            access_token=admin_user_tok,
        )
        self.pump(1.0)
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(
            channel.json_body, {"num_quarantined": 2}, "Expected 2 quarantined items"
        )

        # Convert mxc URLs to server/media_id strings
        server_and_media_id_1 = mxc_1[6:]
        server_and_media_id_2 = mxc_2[6:]

        # Test that we cannot download any of the media anymore
        self._ensure_quarantined(admin_user_tok, server_and_media_id_1)
        self._ensure_quarantined(admin_user_tok, server_and_media_id_2)

    def test_quarantine_all_media_by_user(self) -> None:
        self.register_user("user_admin", "pass", admin=True)
        admin_user_tok = self.login("user_admin", "pass")

        non_admin_user = self.register_user("user_nonadmin", "pass", admin=False)
        non_admin_user_tok = self.login("user_nonadmin", "pass")

        # Upload some media
        response_1 = self.helper.upload_media(SMALL_PNG, tok=non_admin_user_tok)
        response_2 = self.helper.upload_media(SMALL_PNG, tok=non_admin_user_tok)

        # Extract media IDs
        server_and_media_id_1 = response_1["content_uri"][6:]
        server_and_media_id_2 = response_2["content_uri"][6:]

        # Quarantine all media by this user
        url = "/_synapse/admin/v1/user/%s/media/quarantine" % urllib.parse.quote(
            non_admin_user
        )
        channel = self.make_request(
            "POST",
            url.encode("ascii"),
            access_token=admin_user_tok,
        )
        self.pump(1.0)
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(
            channel.json_body, {"num_quarantined": 2}, "Expected 2 quarantined items"
        )

        # Attempt to access each piece of media
        self._ensure_quarantined(admin_user_tok, server_and_media_id_1)
        self._ensure_quarantined(admin_user_tok, server_and_media_id_2)

    def test_cannot_quarantine_safe_media(self) -> None:
        self.register_user("user_admin", "pass", admin=True)
        admin_user_tok = self.login("user_admin", "pass")

        non_admin_user = self.register_user("user_nonadmin", "pass", admin=False)
        non_admin_user_tok = self.login("user_nonadmin", "pass")

        # Upload some media
        response_1 = self.helper.upload_media(SMALL_PNG, tok=non_admin_user_tok)
        response_2 = self.helper.upload_media(SMALL_PNG, tok=non_admin_user_tok)

        # Extract media IDs
        server_and_media_id_1 = response_1["content_uri"][6:]
        server_and_media_id_2 = response_2["content_uri"][6:]

        # Mark the second item as safe from quarantine.
        _, media_id_2 = server_and_media_id_2.split("/")
        # Quarantine the media
        url = "/_synapse/admin/v1/media/protect/%s" % (urllib.parse.quote(media_id_2),)
        channel = self.make_request("POST", url, access_token=admin_user_tok)
        self.pump(1.0)
        self.assertEqual(200, channel.code, msg=channel.json_body)

        # Quarantine all media by this user
        url = "/_synapse/admin/v1/user/%s/media/quarantine" % urllib.parse.quote(
            non_admin_user
        )
        channel = self.make_request(
            "POST",
            url.encode("ascii"),
            access_token=admin_user_tok,
        )
        self.pump(1.0)
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(
            channel.json_body, {"num_quarantined": 1}, "Expected 1 quarantined item"
        )

        # Attempt to access each piece of media, the first should fail, the
        # second should succeed.
        self._ensure_quarantined(admin_user_tok, server_and_media_id_1)

        # Attempt to access each piece of media
        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/{server_and_media_id_2}",
            shorthand=False,
            access_token=non_admin_user_tok,
        )

        # Shouldn't be quarantined
        self.assertEqual(
            200,
            channel.code,
            msg=(
                "Expected to receive a 200 on accessing not-quarantined media: %s"
                % server_and_media_id_2
            ),
        )


class PurgeHistoryTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.room_id = self.helper.create_room_as(
            self.other_user, tok=self.other_user_tok
        )
        self.url = f"/_synapse/admin/v1/purge_history/{self.room_id}"
        self.url_status = "/_synapse/admin/v1/purge_history_status/"

    def test_purge_history(self) -> None:
        """
        Simple test of purge history API.
        Test only that is is possible to call, get status 200 and purge_id.
        """

        channel = self.make_request(
            "POST",
            self.url,
            content={"delete_local_events": True, "purge_up_to_ts": 0},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertIn("purge_id", channel.json_body)
        purge_id = channel.json_body["purge_id"]

        # get status
        channel = self.make_request(
            "GET",
            self.url_status + purge_id,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual("complete", channel.json_body["status"])


class ExperimentalFeaturesTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.url = "/_synapse/admin/v1/experimental_features"

    def test_enable_and_disable(self) -> None:
        """
        Test basic functionality of ExperimentalFeatures endpoint
        """
        # test enabling features works
        url = f"{self.url}/{self.other_user}"
        channel = self.make_request(
            "PUT",
            url,
            content={
                "features": {"msc3026": True, "msc3881": True},
            },
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200)

        # list which features are enabled and ensure the ones we enabled are listed
        self.assertEqual(channel.code, 200)
        url = f"{self.url}/{self.other_user}"
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            True,
            channel.json_body["features"]["msc3026"],
        )
        self.assertEqual(
            True,
            channel.json_body["features"]["msc3881"],
        )

        # test disabling a feature works
        url = f"{self.url}/{self.other_user}"
        channel = self.make_request(
            "PUT",
            url,
            content={"features": {"msc3026": False}},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200)

        # list the features enabled/disabled and ensure they are still are correct
        self.assertEqual(channel.code, 200)
        url = f"{self.url}/{self.other_user}"
        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            False,
            channel.json_body["features"]["msc3026"],
        )
        self.assertEqual(
            True,
            channel.json_body["features"]["msc3881"],
        )
        self.assertEqual(
            False,
            channel.json_body["features"]["msc3967"],
        )

        # test nothing blows up if you try to disable a feature that isn't already enabled
        url = f"{self.url}/{self.other_user}"
        channel = self.make_request(
            "PUT",
            url,
            content={"features": {"msc3026": False}},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 200)

        # test trying to enable a feature without an admin access token is denied
        url = f"{self.url}/f{self.other_user}"
        channel = self.make_request(
            "PUT",
            url,
            content={"features": {"msc3881": True}},
            access_token=self.other_user_tok,
        )
        self.assertEqual(channel.code, 403)
        self.assertEqual(
            channel.json_body,
            {"errcode": "M_FORBIDDEN", "error": "You are not a server admin"},
        )

        # test trying to enable a bogus msc is denied
        url = f"{self.url}/{self.other_user}"
        channel = self.make_request(
            "PUT",
            url,
            content={"features": {"msc6666": True}},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(channel.code, 400)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "'msc6666' is not recognised as a valid experimental feature.",
            },
        )
