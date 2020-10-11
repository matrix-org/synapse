# -*- coding: utf-8 -*-
# Copyright 2020 Dirk Klimpel
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
from binascii import unhexlify

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login
from synapse.rest.media.v1.filepath import MediaFilePaths

from tests import unittest


class DeleteMediaByIDTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.admin.register_servlets_for_media_repo,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.handler = hs.get_device_handler()
        self.media_repo = hs.get_media_repository_resource()
        self.server_name = hs.hostname

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.filepaths = MediaFilePaths(hs.config.media_store_path)

    def test_no_auth(self):
        """
        Try to delete media without authentication.
        """
        url = "/_synapse/admin/v1/media/%s/%s" % (self.server_name, "12345")

        request, channel = self.make_request("DELETE", url, b"{}")
        self.render(request)

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error is returned.
        """
        self.other_user = self.register_user("user", "pass")
        self.other_user_token = self.login("user", "pass")

        url = "/_synapse/admin/v1/media/%s/%s" % (self.server_name, "12345")

        request, channel = self.make_request(
            "DELETE", url, access_token=self.other_user_token,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_media_does_not_exist(self):
        """
        Tests that a lookup for a media that does not exist returns a 404
        """
        url = "/_synapse/admin/v1/media/%s/%s" % (self.server_name, "12345")

        request, channel = self.make_request(
            "DELETE", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_media_is_not_local(self):
        """
        Tests that a lookup for a media that is not a local returns a 400
        """
        url = "/_synapse/admin/v1/media/%s/%s" % ("unknown_domain", "12345")

        request, channel = self.make_request(
            "DELETE", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only delete local media", channel.json_body["error"])

    def test_delete_media(self):
        """
        Tests that delete a media is successfully
        """

        download_resource = self.media_repo.children[b"download"]
        upload_resource = self.media_repo.children[b"upload"]
        image_data = unhexlify(
            b"89504e470d0a1a0a0000000d4948445200000001000000010806"
            b"0000001f15c4890000000a49444154789c63000100000500010d"
            b"0a2db40000000049454e44ae426082"
        )

        # Upload some media into the room
        response = self.helper.upload_media(
            upload_resource, image_data, tok=self.admin_user_tok, expect_code=200
        )
        # Extract media ID from the response
        server_and_media_id = response["content_uri"][6:]  # Cut off 'mxc://'
        server_name, media_id = server_and_media_id.split("/")

        self.assertEqual(server_name, self.server_name)

        # Attempt to access media
        request, channel = self.make_request(
            "GET",
            server_and_media_id,
            shorthand=False,
            access_token=self.admin_user_tok,
        )
        request.render(download_resource)
        self.pump(1.0)

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
        request, channel = self.make_request(
            "DELETE", url, access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(1, channel.json_body["deleted"])

        # Attempt to access media
        request, channel = self.make_request(
            "GET",
            server_and_media_id,
            shorthand=False,
            access_token=self.admin_user_tok,
        )
        request.render(download_resource)
        self.pump(1.0)
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
