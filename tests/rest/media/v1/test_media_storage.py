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
import os
import shutil
import tempfile
from binascii import unhexlify
from io import BytesIO
from typing import Any, BinaryIO, Dict, List, Optional, Union
from unittest.mock import Mock
from urllib import parse

import attr
from parameterized import parameterized, parameterized_class
from PIL import Image as Image
from typing_extensions import Literal

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import Codes
from synapse.events import EventBase
from synapse.events.spamcheck import load_legacy_spam_checkers
from synapse.logging.context import make_deferred_yieldable
from synapse.module_api import ModuleApi
from synapse.rest import admin
from synapse.rest.client import login
from synapse.rest.media.v1._base import FileInfo
from synapse.rest.media.v1.filepath import MediaFilePaths
from synapse.rest.media.v1.media_storage import MediaStorage, ReadableFileWrapper
from synapse.rest.media.v1.storage_provider import FileStorageProviderBackend
from synapse.server import HomeServer
from synapse.types import RoomAlias
from synapse.util import Clock

from tests import unittest
from tests.server import FakeChannel, FakeSite, make_request
from tests.test_utils import SMALL_PNG
from tests.utils import default_config


class MediaStorageTests(unittest.HomeserverTestCase):

    needs_threadpool = True

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="synapse-tests-")
        self.addCleanup(shutil.rmtree, self.test_dir)

        self.primary_base_path = os.path.join(self.test_dir, "primary")
        self.secondary_base_path = os.path.join(self.test_dir, "secondary")

        hs.config.media.media_store_path = self.primary_base_path

        storage_providers = [FileStorageProviderBackend(hs, self.secondary_base_path)]

        self.filepaths = MediaFilePaths(self.primary_base_path)
        self.media_storage = MediaStorage(
            hs, self.primary_base_path, self.filepaths, storage_providers
        )

    def test_ensure_media_is_in_local_cache(self) -> None:
        media_id = "some_media_id"
        test_body = "Test\n"

        # First we create a file that is in a storage provider but not in the
        # local primary media store
        rel_path = self.filepaths.local_media_filepath_rel(media_id)
        secondary_path = os.path.join(self.secondary_base_path, rel_path)

        os.makedirs(os.path.dirname(secondary_path))

        with open(secondary_path, "w") as f:
            f.write(test_body)

        # Now we run ensure_media_is_in_local_cache, which should copy the file
        # to the local cache.
        file_info = FileInfo(None, media_id)

        # This uses a real blocking threadpool so we have to wait for it to be
        # actually done :/
        x = defer.ensureDeferred(
            self.media_storage.ensure_media_is_in_local_cache(file_info)
        )

        # Hotloop until the threadpool does its job...
        self.wait_on_thread(x)

        local_path = self.get_success(x)

        self.assertTrue(os.path.exists(local_path))

        # Asserts the file is under the expected local cache directory
        self.assertEqual(
            os.path.commonprefix([self.primary_base_path, local_path]),
            self.primary_base_path,
        )

        with open(local_path) as f:
            body = f.read()

        self.assertEqual(test_body, body)


@attr.s(auto_attribs=True, slots=True, frozen=True)
class _TestImage:
    """An image for testing thumbnailing with the expected results

    Attributes:
        data: The raw image to thumbnail
        content_type: The type of the image as a content type, e.g. "image/png"
        extension: The extension associated with the format, e.g. ".png"
        expected_cropped: The expected bytes from cropped thumbnailing, or None if
            test should just check for success.
        expected_scaled: The expected bytes from scaled thumbnailing, or None if
            test should just check for a valid image returned.
        expected_found: True if the file should exist on the server, or False if
            a 404 is expected.
    """

    data: bytes
    content_type: bytes
    extension: bytes
    expected_cropped: Optional[bytes] = None
    expected_scaled: Optional[bytes] = None
    expected_found: bool = True


@parameterized_class(
    ("test_image",),
    [
        # small png
        (
            _TestImage(
                SMALL_PNG,
                b"image/png",
                b".png",
                unhexlify(
                    b"89504e470d0a1a0a0000000d4948445200000020000000200806"
                    b"000000737a7af40000001a49444154789cedc101010000008220"
                    b"ffaf6e484001000000ef0610200001194334ee0000000049454e"
                    b"44ae426082"
                ),
                unhexlify(
                    b"89504e470d0a1a0a0000000d4948445200000001000000010806"
                    b"0000001f15c4890000000d49444154789c636060606000000005"
                    b"0001a5f645400000000049454e44ae426082"
                ),
            ),
        ),
        # small png with transparency.
        (
            _TestImage(
                unhexlify(
                    b"89504e470d0a1a0a0000000d49484452000000010000000101000"
                    b"00000376ef9240000000274524e5300010194fdae0000000a4944"
                    b"4154789c636800000082008177cd72b60000000049454e44ae426"
                    b"082"
                ),
                b"image/png",
                b".png",
                # Note that we don't check the output since it varies across
                # different versions of Pillow.
            ),
        ),
        # small lossless webp
        (
            _TestImage(
                unhexlify(
                    b"524946461a000000574542505650384c0d0000002f0000001007"
                    b"1011118888fe0700"
                ),
                b"image/webp",
                b".webp",
            ),
        ),
        # an empty file
        (
            _TestImage(
                b"",
                b"image/gif",
                b".gif",
                expected_found=False,
            ),
        ),
    ],
)
class MediaRepoTests(unittest.HomeserverTestCase):

    hijack_auth = True
    user_id = "@test:user"

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:

        self.fetches = []

        def get_file(
            destination: str,
            path: str,
            output_stream: BinaryIO,
            args: Optional[Dict[str, Union[str, List[str]]]] = None,
            max_size: Optional[int] = None,
        ) -> Deferred:
            """
            Returns tuple[int,dict,str,int] of file length, response headers,
            absolute URI, and response code.
            """

            def write_to(r):
                data, response = r
                output_stream.write(data)
                return response

            d = Deferred()
            d.addCallback(write_to)
            self.fetches.append((d, destination, path, args))
            return make_deferred_yieldable(d)

        client = Mock()
        client.get_file = get_file

        self.storage_path = self.mktemp()
        self.media_store_path = self.mktemp()
        os.mkdir(self.storage_path)
        os.mkdir(self.media_store_path)

        config = self.default_config()
        config["media_store_path"] = self.media_store_path
        config["max_image_pixels"] = 2000000

        provider_config = {
            "module": "synapse.rest.media.v1.storage_provider.FileStorageProviderBackend",
            "store_local": True,
            "store_synchronous": False,
            "store_remote": True,
            "config": {"directory": self.storage_path},
        }
        config["media_storage_providers"] = [provider_config]

        hs = self.setup_test_homeserver(config=config, federation_http_client=client)

        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:

        media_resource = hs.get_media_repository_resource()
        self.download_resource = media_resource.children[b"download"]
        self.thumbnail_resource = media_resource.children[b"thumbnail"]
        self.store = hs.get_datastores().main
        self.media_repo = hs.get_media_repository()

        self.media_id = "example.com/12345"

    def _req(
        self, content_disposition: Optional[bytes], include_content_type: bool = True
    ) -> FakeChannel:
        channel = make_request(
            self.reactor,
            FakeSite(self.download_resource, self.reactor),
            "GET",
            self.media_id,
            shorthand=False,
            await_result=False,
        )
        self.pump()

        # We've made one fetch, to example.com, using the media URL, and asking
        # the other server not to do a remote fetch
        self.assertEqual(len(self.fetches), 1)
        self.assertEqual(self.fetches[0][1], "example.com")
        self.assertEqual(
            self.fetches[0][2], "/_matrix/media/r0/download/" + self.media_id
        )
        self.assertEqual(self.fetches[0][3], {"allow_remote": "false"})

        headers = {
            b"Content-Length": [b"%d" % (len(self.test_image.data))],
        }

        if include_content_type:
            headers[b"Content-Type"] = [self.test_image.content_type]

        if content_disposition:
            headers[b"Content-Disposition"] = [content_disposition]

        self.fetches[0][0].callback(
            (self.test_image.data, (len(self.test_image.data), headers))
        )

        self.pump()
        self.assertEqual(channel.code, 200)

        return channel

    def test_handle_missing_content_type(self) -> None:
        channel = self._req(
            b"inline; filename=out" + self.test_image.extension,
            include_content_type=False,
        )
        headers = channel.headers
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            headers.getRawHeaders(b"Content-Type"), [b"application/octet-stream"]
        )

    def test_disposition_filename_ascii(self) -> None:
        """
        If the filename is filename=<ascii> then Synapse will decode it as an
        ASCII string, and use filename= in the response.
        """
        channel = self._req(b"inline; filename=out" + self.test_image.extension)

        headers = channel.headers
        self.assertEqual(
            headers.getRawHeaders(b"Content-Type"), [self.test_image.content_type]
        )
        self.assertEqual(
            headers.getRawHeaders(b"Content-Disposition"),
            [b"inline; filename=out" + self.test_image.extension],
        )

    def test_disposition_filenamestar_utf8escaped(self) -> None:
        """
        If the filename is filename=*utf8''<utf8 escaped> then Synapse will
        correctly decode it as the UTF-8 string, and use filename* in the
        response.
        """
        filename = parse.quote("\u2603".encode()).encode("ascii")
        channel = self._req(
            b"inline; filename*=utf-8''" + filename + self.test_image.extension
        )

        headers = channel.headers
        self.assertEqual(
            headers.getRawHeaders(b"Content-Type"), [self.test_image.content_type]
        )
        self.assertEqual(
            headers.getRawHeaders(b"Content-Disposition"),
            [b"inline; filename*=utf-8''" + filename + self.test_image.extension],
        )

    def test_disposition_none(self) -> None:
        """
        If there is no filename, one isn't passed on in the Content-Disposition
        of the request.
        """
        channel = self._req(None)

        headers = channel.headers
        self.assertEqual(
            headers.getRawHeaders(b"Content-Type"), [self.test_image.content_type]
        )
        self.assertEqual(headers.getRawHeaders(b"Content-Disposition"), None)

    def test_thumbnail_crop(self) -> None:
        """Test that a cropped remote thumbnail is available."""
        self._test_thumbnail(
            "crop", self.test_image.expected_cropped, self.test_image.expected_found
        )

    def test_thumbnail_scale(self) -> None:
        """Test that a scaled remote thumbnail is available."""
        self._test_thumbnail(
            "scale", self.test_image.expected_scaled, self.test_image.expected_found
        )

    def test_invalid_type(self) -> None:
        """An invalid thumbnail type is never available."""
        self._test_thumbnail("invalid", None, False)

    @unittest.override_config(
        {"thumbnail_sizes": [{"width": 32, "height": 32, "method": "scale"}]}
    )
    def test_no_thumbnail_crop(self) -> None:
        """
        Override the config to generate only scaled thumbnails, but request a cropped one.
        """
        self._test_thumbnail("crop", None, False)

    @unittest.override_config(
        {"thumbnail_sizes": [{"width": 32, "height": 32, "method": "crop"}]}
    )
    def test_no_thumbnail_scale(self) -> None:
        """
        Override the config to generate only cropped thumbnails, but request a scaled one.
        """
        self._test_thumbnail("scale", None, False)

    def test_thumbnail_repeated_thumbnail(self) -> None:
        """Test that fetching the same thumbnail works, and deleting the on disk
        thumbnail regenerates it.
        """
        self._test_thumbnail(
            "scale", self.test_image.expected_scaled, self.test_image.expected_found
        )

        if not self.test_image.expected_found:
            return

        # Fetching again should work, without re-requesting the image from the
        # remote.
        params = "?width=32&height=32&method=scale"
        channel = make_request(
            self.reactor,
            FakeSite(self.thumbnail_resource, self.reactor),
            "GET",
            self.media_id + params,
            shorthand=False,
            await_result=False,
        )
        self.pump()

        self.assertEqual(channel.code, 200)
        if self.test_image.expected_scaled:
            self.assertEqual(
                channel.result["body"],
                self.test_image.expected_scaled,
                channel.result["body"],
            )

        # Deleting the thumbnail on disk then re-requesting it should work as
        # Synapse should regenerate missing thumbnails.
        origin, media_id = self.media_id.split("/")
        info = self.get_success(self.store.get_cached_remote_media(origin, media_id))
        file_id = info["filesystem_id"]

        thumbnail_dir = self.media_repo.filepaths.remote_media_thumbnail_dir(
            origin, file_id
        )
        shutil.rmtree(thumbnail_dir, ignore_errors=True)

        channel = make_request(
            self.reactor,
            FakeSite(self.thumbnail_resource, self.reactor),
            "GET",
            self.media_id + params,
            shorthand=False,
            await_result=False,
        )
        self.pump()

        self.assertEqual(channel.code, 200)
        if self.test_image.expected_scaled:
            self.assertEqual(
                channel.result["body"],
                self.test_image.expected_scaled,
                channel.result["body"],
            )

    def _test_thumbnail(
        self, method: str, expected_body: Optional[bytes], expected_found: bool
    ) -> None:
        params = "?width=32&height=32&method=" + method
        channel = make_request(
            self.reactor,
            FakeSite(self.thumbnail_resource, self.reactor),
            "GET",
            self.media_id + params,
            shorthand=False,
            await_result=False,
        )
        self.pump()

        headers = {
            b"Content-Length": [b"%d" % (len(self.test_image.data))],
            b"Content-Type": [self.test_image.content_type],
        }
        self.fetches[0][0].callback(
            (self.test_image.data, (len(self.test_image.data), headers))
        )
        self.pump()

        if expected_found:
            self.assertEqual(channel.code, 200)

            self.assertEqual(
                channel.headers.getRawHeaders(b"Cross-Origin-Resource-Policy"),
                [b"cross-origin"],
            )

            if expected_body is not None:
                self.assertEqual(
                    channel.result["body"], expected_body, channel.result["body"]
                )
            else:
                # ensure that the result is at least some valid image
                Image.open(BytesIO(channel.result["body"]))
        else:
            # A 404 with a JSON body.
            self.assertEqual(channel.code, 404)
            self.assertEqual(
                channel.json_body,
                {
                    "errcode": "M_NOT_FOUND",
                    "error": "Not found [b'example.com', b'12345']",
                },
            )

    @parameterized.expand([("crop", 16), ("crop", 64), ("scale", 16), ("scale", 64)])
    def test_same_quality(self, method: str, desired_size: int) -> None:
        """Test that choosing between thumbnails with the same quality rating succeeds.

        We are not particular about which thumbnail is chosen."""
        self.assertIsNotNone(
            self.thumbnail_resource._select_thumbnail(
                desired_width=desired_size,
                desired_height=desired_size,
                desired_method=method,
                desired_type=self.test_image.content_type,
                # Provide two identical thumbnails which are guaranteed to have the same
                # quality rating.
                thumbnail_infos=[
                    {
                        "thumbnail_width": 32,
                        "thumbnail_height": 32,
                        "thumbnail_method": method,
                        "thumbnail_type": self.test_image.content_type,
                        "thumbnail_length": 256,
                        "filesystem_id": f"thumbnail1{self.test_image.extension}",
                    },
                    {
                        "thumbnail_width": 32,
                        "thumbnail_height": 32,
                        "thumbnail_method": method,
                        "thumbnail_type": self.test_image.content_type,
                        "thumbnail_length": 256,
                        "filesystem_id": f"thumbnail2{self.test_image.extension}",
                    },
                ],
                file_id=f"image{self.test_image.extension}",
                url_cache=None,
                server_name=None,
            )
        )

    def test_x_robots_tag_header(self) -> None:
        """
        Tests that the `X-Robots-Tag` header is present, which informs web crawlers
        to not index, archive, or follow links in media.
        """
        channel = self._req(b"inline; filename=out" + self.test_image.extension)

        headers = channel.headers
        self.assertEqual(
            headers.getRawHeaders(b"X-Robots-Tag"),
            [b"noindex, nofollow, noarchive, noimageindex"],
        )

    def test_cross_origin_resource_policy_header(self) -> None:
        """
        Test that the Cross-Origin-Resource-Policy header is set to "cross-origin"
        allowing web clients to embed media from the downloads API.
        """
        channel = self._req(b"inline; filename=out" + self.test_image.extension)

        headers = channel.headers

        self.assertEqual(
            headers.getRawHeaders(b"Cross-Origin-Resource-Policy"),
            [b"cross-origin"],
        )


class TestSpamCheckerLegacy:
    """A spam checker module that rejects all media that includes the bytes
    `evil`.

    Uses the legacy Spam-Checker API.
    """

    def __init__(self, config: Dict[str, Any], api: ModuleApi) -> None:
        self.config = config
        self.api = api

    def parse_config(config: Dict[str, Any]) -> Dict[str, Any]:
        return config

    async def check_event_for_spam(self, event: EventBase) -> Union[bool, str]:
        return False  # allow all events

    async def user_may_invite(
        self,
        inviter_userid: str,
        invitee_userid: str,
        room_id: str,
    ) -> bool:
        return True  # allow all invites

    async def user_may_create_room(self, userid: str) -> bool:
        return True  # allow all room creations

    async def user_may_create_room_alias(
        self, userid: str, room_alias: RoomAlias
    ) -> bool:
        return True  # allow all room aliases

    async def user_may_publish_room(self, userid: str, room_id: str) -> bool:
        return True  # allow publishing of all rooms

    async def check_media_file_for_spam(
        self, file_wrapper: ReadableFileWrapper, file_info: FileInfo
    ) -> bool:
        buf = BytesIO()
        await file_wrapper.write_chunks_to(buf.write)

        return b"evil" in buf.getvalue()


class SpamCheckerTestCaseLegacy(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
        admin.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user = self.register_user("user", "pass")
        self.tok = self.login("user", "pass")

        # Allow for uploading and downloading to/from the media repo
        self.media_repo = hs.get_media_repository_resource()
        self.download_resource = self.media_repo.children[b"download"]
        self.upload_resource = self.media_repo.children[b"upload"]

        load_legacy_spam_checkers(hs)

    def default_config(self) -> Dict[str, Any]:
        config = default_config("test")

        config.update(
            {
                "spam_checker": [
                    {
                        "module": TestSpamCheckerLegacy.__module__
                        + ".TestSpamCheckerLegacy",
                        "config": {},
                    }
                ]
            }
        )

        return config

    def test_upload_innocent(self) -> None:
        """Attempt to upload some innocent data that should be allowed."""
        self.helper.upload_media(
            self.upload_resource, SMALL_PNG, tok=self.tok, expect_code=200
        )

    def test_upload_ban(self) -> None:
        """Attempt to upload some data that includes bytes "evil", which should
        get rejected by the spam checker.
        """

        data = b"Some evil data"

        self.helper.upload_media(
            self.upload_resource, data, tok=self.tok, expect_code=400
        )


EVIL_DATA = b"Some evil data"
EVIL_DATA_EXPERIMENT = b"Some evil data to trigger the experimental tuple API"


class SpamCheckerTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
        admin.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user = self.register_user("user", "pass")
        self.tok = self.login("user", "pass")

        # Allow for uploading and downloading to/from the media repo
        self.media_repo = hs.get_media_repository_resource()
        self.download_resource = self.media_repo.children[b"download"]
        self.upload_resource = self.media_repo.children[b"upload"]

        hs.get_module_api().register_spam_checker_callbacks(
            check_media_file_for_spam=self.check_media_file_for_spam
        )

    async def check_media_file_for_spam(
        self, file_wrapper: ReadableFileWrapper, file_info: FileInfo
    ) -> Union[Codes, Literal["NOT_SPAM"]]:
        buf = BytesIO()
        await file_wrapper.write_chunks_to(buf.write)

        if buf.getvalue() == EVIL_DATA:
            return Codes.FORBIDDEN
        elif buf.getvalue() == EVIL_DATA_EXPERIMENT:
            return (Codes.FORBIDDEN, {})
        else:
            return "NOT_SPAM"

    def test_upload_innocent(self) -> None:
        """Attempt to upload some innocent data that should be allowed."""
        self.helper.upload_media(
            self.upload_resource, SMALL_PNG, tok=self.tok, expect_code=200
        )

    def test_upload_ban(self) -> None:
        """Attempt to upload some data that includes bytes "evil", which should
        get rejected by the spam checker.
        """

        self.helper.upload_media(
            self.upload_resource, EVIL_DATA, tok=self.tok, expect_code=400
        )

        self.helper.upload_media(
            self.upload_resource,
            EVIL_DATA_EXPERIMENT,
            tok=self.tok,
            expect_code=400,
        )
