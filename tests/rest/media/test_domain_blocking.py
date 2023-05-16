# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from typing import Dict

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.media._base import FileInfo
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.test_utils import SMALL_PNG
from tests.unittest import override_config


class MediaDomainBlockingTests(unittest.HomeserverTestCase):
    remote_media_id = "doesnotmatter"
    remote_server_name = "evil.com"

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        # Inject a piece of media. We'll use this to ensure we're returning a sane
        # response when we're not supposed to block it, distinguishing a media block
        # from a regular 404.
        file_id = "abcdefg12345"
        file_info = FileInfo(server_name=self.remote_server_name, file_id=file_id)
        with hs.get_media_repository().media_storage.store_into_file(file_info) as (
            f,
            fname,
            finish,
        ):
            f.write(SMALL_PNG)
            self.get_success(finish())

        self.get_success(
            self.store.store_cached_remote_media(
                origin=self.remote_server_name,
                media_id=self.remote_media_id,
                media_type="image/png",
                media_length=1,
                time_now_ms=clock.time_msec(),
                upload_name="test.png",
                filesystem_id=file_id,
            )
        )

    def create_resource_dict(self) -> Dict[str, Resource]:
        # We need to manually set the resource tree to include media, the
        # default only does `/_matrix/client` APIs.
        return {"/_matrix/media": self.hs.get_media_repository_resource()}

    @override_config(
        {
            # Disable downloads from the domain we'll be trying to download from.
            # Should result in a 404.
            "prevent_media_downloads_from": ["evil.com"]
        }
    )
    def test_cannot_download_blocked_media(self) -> None:
        """
        Tests to ensure that remote media which is blocked cannot be downloaded.
        """
        response = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/evil.com/{self.remote_media_id}",
            shorthand=False,
        )
        self.assertEqual(response.code, 404)

    @override_config(
        {
            # Disable downloads from a domain we won't be requesting downloads from.
            # This proves we haven't broken anything.
            "prevent_media_downloads_from": ["not-listed.com"]
        }
    )
    def test_remote_media_normally_unblocked(self) -> None:
        """
        Tests to ensure that remote media is normally able to be downloaded
        when no domain block is in place.
        """
        response = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/evil.com/{self.remote_media_id}",
            shorthand=False,
        )
        self.assertEqual(response.code, 200)

    @override_config(
        {
            # Disable downloads from the domain we'll be trying to download from.
            # Should result in a 404.
            "prevent_media_downloads_from": ["evil.com"],
            "dynamic_thumbnails": True,
        }
    )
    def test_cannot_download_blocked_media_thumbnail(self) -> None:
        """
        Same test as test_cannot_download_blocked_media but for thumbnails.
        """
        response = self.make_request(
            "GET",
            f"/_matrix/media/v3/thumbnail/evil.com/{self.remote_media_id}?width=100&height=100",
            shorthand=False,
            content={"width": 100, "height": 100},
        )
        self.assertEqual(response.code, 404)

    @override_config(
        {
            # Disable downloads from a domain we won't be requesting downloads from.
            # This proves we haven't broken anything.
            "prevent_media_downloads_from": ["not-listed.com"],
            "dynamic_thumbnails": True,
        }
    )
    def test_remote_media_thumbnail_normally_unblocked(self) -> None:
        """
        Same test as test_remote_media_normally_unblocked but for thumbnails.
        """
        response = self.make_request(
            "GET",
            f"/_matrix/media/v3/thumbnail/evil.com/{self.remote_media_id}?width=100&height=100",
            shorthand=False,
        )
        self.assertEqual(response.code, 200)
