# Copyright 2020 Dirk Klimpel
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
import os

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client import login, profile, room
from synapse.rest.media.v1.filepath import MediaFilePaths
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.server import FakeSite, make_request
from tests.test_utils import SMALL_PNG

VALID_TIMESTAMP = 1609459200000  # 2021-01-01 in milliseconds
INVALID_TIMESTAMP_IN_S = 1893456000  # 2030-01-01 in seconds


class DeleteMediaByIDTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.admin.register_servlets_for_media_repo,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.media_repo = hs.get_media_repository_resource()
        self.server_name = hs.hostname

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.filepaths = MediaFilePaths(hs.config.media.media_store_path)

    def test_no_auth(self) -> None:
        """
        Try to delete media without authentication.
        """
        url = "/_synapse/admin/v1/media/%s/%s" % (self.server_name, "12345")

        channel = self.make_request("DELETE", url, b"{}")

        self.assertEqual(
            401,
            channel.code,
            msg=channel.json_body,
        )
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        url = "/_synapse/admin/v1/media/%s/%s" % (self.server_name, "12345")

        channel = self.make_request(
            "DELETE",
            url,
            access_token=self.other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_media_does_not_exist(self) -> None:
        """
        Tests that a lookup for a media that does not exist returns a 404
        """
        url = "/_synapse/admin/v1/media/%s/%s" % (self.server_name, "12345")

        channel = self.make_request(
            "DELETE",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_media_is_not_local(self) -> None:
        """
        Tests that a lookup for a media that is not a local returns a 400
        """
        url = "/_synapse/admin/v1/media/%s/%s" % ("unknown_domain", "12345")

        channel = self.make_request(
            "DELETE",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only delete local media", channel.json_body["error"])

    def test_delete_media(self) -> None:
        """
        Tests that delete a media is successfully
        """

        download_resource = self.media_repo.children[b"download"]
        upload_resource = self.media_repo.children[b"upload"]

        # Upload some media into the room
        response = self.helper.upload_media(
            upload_resource,
            SMALL_PNG,
            tok=self.admin_user_tok,
            expect_code=200,
        )
        # Extract media ID from the response
        server_and_media_id = response["content_uri"][6:]  # Cut off 'mxc://'
        server_name, media_id = server_and_media_id.split("/")

        self.assertEqual(server_name, self.server_name)

        # Attempt to access media
        channel = make_request(
            self.reactor,
            FakeSite(download_resource, self.reactor),
            "GET",
            server_and_media_id,
            shorthand=False,
            access_token=self.admin_user_tok,
        )

        # Should be successful
        self.assertEqual(
            200,
            channel.code,
            msg=(
                "Expected to receive a 200 on accessing media: %s" % server_and_media_id
            ),
        )

        # Test if the file exists
        local_path = self.filepaths.local_media_filepath(media_id)
        self.assertTrue(os.path.exists(local_path))

        url = "/_synapse/admin/v1/media/%s/%s" % (self.server_name, media_id)

        # Delete media
        channel = self.make_request(
            "DELETE",
            url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])
        self.assertEqual(
            media_id,
            channel.json_body["deleted_media"][0],
        )

        # Attempt to access media
        channel = make_request(
            self.reactor,
            FakeSite(download_resource, self.reactor),
            "GET",
            server_and_media_id,
            shorthand=False,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(
            404,
            channel.code,
            msg=(
                "Expected to receive a 404 on accessing deleted media: %s"
                % server_and_media_id
            ),
        )

        # Test if the file is deleted
        self.assertFalse(os.path.exists(local_path))


class DeleteMediaByDateSizeTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.admin.register_servlets_for_media_repo,
        login.register_servlets,
        profile.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.media_repo = hs.get_media_repository_resource()
        self.server_name = hs.hostname

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.filepaths = MediaFilePaths(hs.config.media.media_store_path)
        self.url = "/_synapse/admin/v1/media/%s/delete" % self.server_name

        # Move clock up to somewhat realistic time
        self.reactor.advance(1000000000)

    def test_no_auth(self) -> None:
        """
        Try to delete media without authentication.
        """

        channel = self.make_request("POST", self.url, b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_media_is_not_local(self) -> None:
        """
        Tests that a lookup for media that is not local returns a 400
        """
        url = "/_synapse/admin/v1/media/%s/delete" % "unknown_domain"

        channel = self.make_request(
            "POST",
            url + f"?before_ts={VALID_TIMESTAMP}",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only delete local media", channel.json_body["error"])

    def test_missing_parameter(self) -> None:
        """
        If the parameter `before_ts` is missing, an error is returned.
        """
        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Missing integer query parameter 'before_ts'", channel.json_body["error"]
        )

    def test_invalid_parameter(self) -> None:
        """
        If parameters are invalid, an error is returned.
        """
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=-1234",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter before_ts must be a positive integer.",
            channel.json_body["error"],
        )

        channel = self.make_request(
            "POST",
            self.url + f"?before_ts={INVALID_TIMESTAMP_IN_S}",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter before_ts you provided is from the year 1970. "
            + "Double check that you are providing a timestamp in milliseconds.",
            channel.json_body["error"],
        )

        channel = self.make_request(
            "POST",
            self.url + f"?before_ts={VALID_TIMESTAMP}&size_gt=-1234",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter size_gt must be a string representing a positive integer.",
            channel.json_body["error"],
        )

        channel = self.make_request(
            "POST",
            self.url + f"?before_ts={VALID_TIMESTAMP}&keep_profiles=not_bool",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Boolean query parameter 'keep_profiles' must be one of ['true', 'false']",
            channel.json_body["error"],
        )

    def test_delete_media_never_accessed(self) -> None:
        """
        Tests that media deleted if it is older than `before_ts` and never accessed
        `last_access_ts` is `NULL` and `created_ts` < `before_ts`
        """

        # upload and do not access
        server_and_media_id = self._create_media()
        self.pump(1.0)

        # test that the file exists
        media_id = server_and_media_id.split("/")[1]
        local_path = self.filepaths.local_media_filepath(media_id)
        self.assertTrue(os.path.exists(local_path))

        # timestamp after upload/create
        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])
        self.assertEqual(
            media_id,
            channel.json_body["deleted_media"][0],
        )

        self._access_media(server_and_media_id, False)

    def test_keep_media_by_date(self) -> None:
        """
        Tests that media is not deleted if it is newer than `before_ts`
        """

        # timestamp before upload
        now_ms = self.clock.time_msec()
        server_and_media_id = self._create_media()

        self._access_media(server_and_media_id)

        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])

        self._access_media(server_and_media_id)

        # timestamp after upload
        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms),
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])
        self.assertEqual(
            server_and_media_id.split("/")[1],
            channel.json_body["deleted_media"][0],
        )

        self._access_media(server_and_media_id, False)

    def test_keep_media_by_size(self) -> None:
        """
        Tests that media is not deleted if its size is smaller than or equal
        to `size_gt`
        """
        server_and_media_id = self._create_media()

        self._access_media(server_and_media_id)

        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms) + "&size_gt=67",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])

        self._access_media(server_and_media_id)

        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms) + "&size_gt=66",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])
        self.assertEqual(
            server_and_media_id.split("/")[1],
            channel.json_body["deleted_media"][0],
        )

        self._access_media(server_and_media_id, False)

    def test_keep_media_by_user_avatar(self) -> None:
        """
        Tests that we do not delete media if is used as a user avatar
        Tests parameter `keep_profiles`
        """
        server_and_media_id = self._create_media()

        self._access_media(server_and_media_id)

        # set media as avatar
        channel = self.make_request(
            "PUT",
            "/profile/%s/avatar_url" % (self.admin_user,),
            content={"avatar_url": "mxc://%s" % (server_and_media_id,)},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms) + "&keep_profiles=true",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])

        self._access_media(server_and_media_id)

        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms) + "&keep_profiles=false",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])
        self.assertEqual(
            server_and_media_id.split("/")[1],
            channel.json_body["deleted_media"][0],
        )

        self._access_media(server_and_media_id, False)

    def test_keep_media_by_room_avatar(self) -> None:
        """
        Tests that we do not delete media if it is used as a room avatar
        Tests parameter `keep_profiles`
        """
        server_and_media_id = self._create_media()

        self._access_media(server_and_media_id)

        # set media as room avatar
        room_id = self.helper.create_room_as(self.admin_user, tok=self.admin_user_tok)
        channel = self.make_request(
            "PUT",
            "/rooms/%s/state/m.room.avatar" % (room_id,),
            content={"url": "mxc://%s" % (server_and_media_id,)},
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)

        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms) + "&keep_profiles=true",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(0, channel.json_body["total"])

        self._access_media(server_and_media_id)

        now_ms = self.clock.time_msec()
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=" + str(now_ms) + "&keep_profiles=false",
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["total"])
        self.assertEqual(
            server_and_media_id.split("/")[1],
            channel.json_body["deleted_media"][0],
        )

        self._access_media(server_and_media_id, False)

    def _create_media(self) -> str:
        """
        Create a media and return media_id and server_and_media_id
        """
        upload_resource = self.media_repo.children[b"upload"]

        # Upload some media into the room
        response = self.helper.upload_media(
            upload_resource,
            SMALL_PNG,
            tok=self.admin_user_tok,
            expect_code=200,
        )
        # Extract media ID from the response
        server_and_media_id = response["content_uri"][6:]  # Cut off 'mxc://'
        server_name = server_and_media_id.split("/")[0]

        # Check that new media is a local and not remote
        self.assertEqual(server_name, self.server_name)

        return server_and_media_id

    def _access_media(
        self, server_and_media_id: str, expect_success: bool = True
    ) -> None:
        """
        Try to access a media and check the result
        """
        download_resource = self.media_repo.children[b"download"]

        media_id = server_and_media_id.split("/")[1]
        local_path = self.filepaths.local_media_filepath(media_id)

        channel = make_request(
            self.reactor,
            FakeSite(download_resource, self.reactor),
            "GET",
            server_and_media_id,
            shorthand=False,
            access_token=self.admin_user_tok,
        )

        if expect_success:
            self.assertEqual(
                200,
                channel.code,
                msg=(
                    "Expected to receive a 200 on accessing media: %s"
                    % server_and_media_id
                ),
            )
            # Test that the file exists
            self.assertTrue(os.path.exists(local_path))
        else:
            self.assertEqual(
                404,
                channel.code,
                msg=(
                    "Expected to receive a 404 on accessing deleted media: %s"
                    % (server_and_media_id)
                ),
            )
            # Test that the file is deleted
            self.assertFalse(os.path.exists(local_path))


class QuarantineMediaByIDTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.admin.register_servlets_for_media_repo,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        media_repo = hs.get_media_repository_resource()
        self.store = hs.get_datastores().main
        self.server_name = hs.hostname

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        # Create media
        upload_resource = media_repo.children[b"upload"]

        # Upload some media into the room
        response = self.helper.upload_media(
            upload_resource,
            SMALL_PNG,
            tok=self.admin_user_tok,
            expect_code=200,
        )
        # Extract media ID from the response
        server_and_media_id = response["content_uri"][6:]  # Cut off 'mxc://'
        self.media_id = server_and_media_id.split("/")[1]

        self.url = "/_synapse/admin/v1/media/%s/%s/%s"

    @parameterized.expand(["quarantine", "unquarantine"])
    def test_no_auth(self, action: str) -> None:
        """
        Try to protect media without authentication.
        """

        channel = self.make_request(
            "POST",
            self.url % (action, self.server_name, self.media_id),
            b"{}",
        )

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    @parameterized.expand(["quarantine", "unquarantine"])
    def test_requester_is_no_admin(self, action: str) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "POST",
            self.url % (action, self.server_name, self.media_id),
            access_token=self.other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_quarantine_media(self) -> None:
        """
        Tests that quarantining and remove from quarantine a media is successfully
        """

        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertFalse(media_info["quarantined_by"])

        # quarantining
        channel = self.make_request(
            "POST",
            self.url % ("quarantine", self.server_name, self.media_id),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertFalse(channel.json_body)

        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertTrue(media_info["quarantined_by"])

        # remove from quarantine
        channel = self.make_request(
            "POST",
            self.url % ("unquarantine", self.server_name, self.media_id),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertFalse(channel.json_body)

        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertFalse(media_info["quarantined_by"])

    def test_quarantine_protected_media(self) -> None:
        """
        Tests that quarantining from protected media fails
        """

        # protect
        self.get_success(self.store.mark_local_media_as_safe(self.media_id, safe=True))

        # verify protection
        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertTrue(media_info["safe_from_quarantine"])

        # quarantining
        channel = self.make_request(
            "POST",
            self.url % ("quarantine", self.server_name, self.media_id),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertFalse(channel.json_body)

        # verify that is not in quarantine
        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertFalse(media_info["quarantined_by"])


class ProtectMediaByIDTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.admin.register_servlets_for_media_repo,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        media_repo = hs.get_media_repository_resource()
        self.store = hs.get_datastores().main

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        # Create media
        upload_resource = media_repo.children[b"upload"]

        # Upload some media into the room
        response = self.helper.upload_media(
            upload_resource,
            SMALL_PNG,
            tok=self.admin_user_tok,
            expect_code=200,
        )
        # Extract media ID from the response
        server_and_media_id = response["content_uri"][6:]  # Cut off 'mxc://'
        self.media_id = server_and_media_id.split("/")[1]

        self.url = "/_synapse/admin/v1/media/%s/%s"

    @parameterized.expand(["protect", "unprotect"])
    def test_no_auth(self, action: str) -> None:
        """
        Try to protect media without authentication.
        """

        channel = self.make_request("POST", self.url % (action, self.media_id), b"{}")

        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    @parameterized.expand(["protect", "unprotect"])
    def test_requester_is_no_admin(self, action: str) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "POST",
            self.url % (action, self.media_id),
            access_token=self.other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_protect_media(self) -> None:
        """
        Tests that protect and unprotect a media is successfully
        """

        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertFalse(media_info["safe_from_quarantine"])

        # protect
        channel = self.make_request(
            "POST",
            self.url % ("protect", self.media_id),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertFalse(channel.json_body)

        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertTrue(media_info["safe_from_quarantine"])

        # unprotect
        channel = self.make_request(
            "POST",
            self.url % ("unprotect", self.media_id),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertFalse(channel.json_body)

        media_info = self.get_success(self.store.get_local_media(self.media_id))
        assert media_info is not None
        self.assertFalse(media_info["safe_from_quarantine"])


class PurgeMediaCacheTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.admin.register_servlets_for_media_repo,
        login.register_servlets,
        profile.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.media_repo = hs.get_media_repository_resource()
        self.server_name = hs.hostname

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.filepaths = MediaFilePaths(hs.config.media.media_store_path)
        self.url = "/_synapse/admin/v1/purge_media_cache"

    def test_no_auth(self) -> None:
        """
        Try to delete media without authentication.
        """

        channel = self.make_request("POST", self.url, b"{}")

        self.assertEqual(
            401,
            channel.code,
            msg=channel.json_body,
        )
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_not_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "POST",
            self.url,
            access_token=self.other_user_token,
        )

        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_invalid_parameter(self) -> None:
        """
        If parameters are invalid, an error is returned.
        """
        channel = self.make_request(
            "POST",
            self.url + "?before_ts=-1234",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter before_ts must be a positive integer.",
            channel.json_body["error"],
        )

        channel = self.make_request(
            "POST",
            self.url + f"?before_ts={INVALID_TIMESTAMP_IN_S}",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter before_ts you provided is from the year 1970. "
            + "Double check that you are providing a timestamp in milliseconds.",
            channel.json_body["error"],
        )
