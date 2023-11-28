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
from typing import Any, BinaryIO, ClassVar, Dict, List, Optional, Tuple, Union
from unittest.mock import Mock
from urllib import parse

import attr
from parameterized import parameterized, parameterized_class
from PIL import Image as Image
from typing_extensions import Literal

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure
from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.api.errors import Codes, HttpResponseException
from synapse.events import EventBase
from synapse.http.types import QueryParams
from synapse.logging.context import make_deferred_yieldable
from synapse.media._base import FileInfo, ThumbnailInfo
from synapse.media.filepath import MediaFilePaths
from synapse.media.media_storage import MediaStorage, ReadableFileWrapper
from synapse.media.storage_provider import FileStorageProviderBackend
from synapse.module_api import ModuleApi
from synapse.module_api.callbacks.spamchecker_callbacks import load_legacy_spam_checkers
from synapse.rest import admin
from synapse.rest.client import login
from synapse.rest.media.thumbnail_resource import ThumbnailResource
from synapse.server import HomeServer
from synapse.types import JsonDict, RoomAlias
from synapse.util import Clock

from tests import unittest
from tests.server import FakeChannel
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
            a 404/400 is expected.
        unable_to_thumbnail: True if we expect the thumbnailing to fail (400), or
            False if the thumbnailing should succeed or a normal 404 is expected.
        is_inline: True if we expect the file to be served using an inline
            Content-Disposition or False if we expect an attachment.
    """

    data: bytes
    content_type: bytes
    extension: bytes
    expected_cropped: Optional[bytes] = None
    expected_scaled: Optional[bytes] = None
    expected_found: bool = True
    unable_to_thumbnail: bool = False
    is_inline: bool = True


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
                unable_to_thumbnail=True,
            ),
        ),
        # An SVG.
        (
            _TestImage(
                b"""<?xml version="1.0"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg xmlns="http://www.w3.org/2000/svg"
     width="400" height="400">
  <circle cx="100" cy="100" r="50" stroke="black"
    stroke-width="5" fill="red" />
</svg>""",
                b"image/svg",
                b".svg",
                expected_found=False,
                unable_to_thumbnail=True,
                is_inline=False,
            ),
        ),
    ],
)
class MediaRepoTests(unittest.HomeserverTestCase):
    test_image: ClassVar[_TestImage]
    hijack_auth = True
    user_id = "@test:user"

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.fetches: List[
            Tuple[
                "Deferred[Tuple[bytes, Tuple[int, Dict[bytes, List[bytes]]]]]",
                str,
                str,
                Optional[QueryParams],
            ]
        ] = []

        def get_file(
            destination: str,
            path: str,
            output_stream: BinaryIO,
            args: Optional[QueryParams] = None,
            retry_on_dns_fail: bool = True,
            max_size: Optional[int] = None,
            ignore_backoff: bool = False,
            follow_redirects: bool = False,
        ) -> "Deferred[Tuple[int, Dict[bytes, List[bytes]]]]":
            """A mock for MatrixFederationHttpClient.get_file."""

            def write_to(
                r: Tuple[bytes, Tuple[int, Dict[bytes, List[bytes]]]]
            ) -> Tuple[int, Dict[bytes, List[bytes]]]:
                data, response = r
                output_stream.write(data)
                return response

            def write_err(f: Failure) -> Failure:
                f.trap(HttpResponseException)
                output_stream.write(f.value.response)
                return f

            d: Deferred[Tuple[bytes, Tuple[int, Dict[bytes, List[bytes]]]]] = Deferred()
            self.fetches.append((d, destination, path, args))
            # Note that this callback changes the value held by d.
            d_after_callback = d.addCallbacks(write_to, write_err)
            return make_deferred_yieldable(d_after_callback)

        # Mock out the homeserver's MatrixFederationHttpClient
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
            "module": "synapse.media.storage_provider.FileStorageProviderBackend",
            "store_local": True,
            "store_synchronous": False,
            "store_remote": True,
            "config": {"directory": self.storage_path},
        }
        config["media_storage_providers"] = [provider_config]

        hs = self.setup_test_homeserver(config=config, federation_http_client=client)

        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.media_repo = hs.get_media_repository()

        self.media_id = "example.com/12345"

    def create_resource_dict(self) -> Dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    def _req(
        self, content_disposition: Optional[bytes], include_content_type: bool = True
    ) -> FakeChannel:
        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/{self.media_id}",
            shorthand=False,
            await_result=False,
        )
        self.pump()

        # We've made one fetch, to example.com, using the media URL, and asking
        # the other server not to do a remote fetch
        self.assertEqual(len(self.fetches), 1)
        self.assertEqual(self.fetches[0][1], "example.com")
        self.assertEqual(
            self.fetches[0][2], "/_matrix/media/v3/download/" + self.media_id
        )
        self.assertEqual(
            self.fetches[0][3],
            {"allow_remote": "false", "timeout_ms": "20000", "allow_redirect": "true"},
        )

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
            b"attachment; filename=out" + self.test_image.extension,
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
        channel = self._req(b"attachment; filename=out" + self.test_image.extension)

        headers = channel.headers
        self.assertEqual(
            headers.getRawHeaders(b"Content-Type"), [self.test_image.content_type]
        )
        self.assertEqual(
            headers.getRawHeaders(b"Content-Disposition"),
            [
                (b"inline" if self.test_image.is_inline else b"attachment")
                + b"; filename=out"
                + self.test_image.extension
            ],
        )

    def test_disposition_filenamestar_utf8escaped(self) -> None:
        """
        If the filename is filename=*utf8''<utf8 escaped> then Synapse will
        correctly decode it as the UTF-8 string, and use filename* in the
        response.
        """
        filename = parse.quote("\u2603".encode()).encode("ascii")
        channel = self._req(
            b"attachment; filename*=utf-8''" + filename + self.test_image.extension
        )

        headers = channel.headers
        self.assertEqual(
            headers.getRawHeaders(b"Content-Type"), [self.test_image.content_type]
        )
        self.assertEqual(
            headers.getRawHeaders(b"Content-Disposition"),
            [
                (b"inline" if self.test_image.is_inline else b"attachment")
                + b"; filename*=utf-8''"
                + filename
                + self.test_image.extension
            ],
        )

    def test_disposition_none(self) -> None:
        """
        If there is no filename, Content-Disposition should only
        be a disposition type.
        """
        channel = self._req(None)

        headers = channel.headers
        self.assertEqual(
            headers.getRawHeaders(b"Content-Type"), [self.test_image.content_type]
        )
        self.assertEqual(
            headers.getRawHeaders(b"Content-Disposition"),
            [b"inline" if self.test_image.is_inline else b"attachment"],
        )

    def test_thumbnail_crop(self) -> None:
        """Test that a cropped remote thumbnail is available."""
        self._test_thumbnail(
            "crop",
            self.test_image.expected_cropped,
            expected_found=self.test_image.expected_found,
            unable_to_thumbnail=self.test_image.unable_to_thumbnail,
        )

    def test_thumbnail_scale(self) -> None:
        """Test that a scaled remote thumbnail is available."""
        self._test_thumbnail(
            "scale",
            self.test_image.expected_scaled,
            expected_found=self.test_image.expected_found,
            unable_to_thumbnail=self.test_image.unable_to_thumbnail,
        )

    def test_invalid_type(self) -> None:
        """An invalid thumbnail type is never available."""
        self._test_thumbnail(
            "invalid",
            None,
            expected_found=False,
            unable_to_thumbnail=self.test_image.unable_to_thumbnail,
        )

    @unittest.override_config(
        {"thumbnail_sizes": [{"width": 32, "height": 32, "method": "scale"}]}
    )
    def test_no_thumbnail_crop(self) -> None:
        """
        Override the config to generate only scaled thumbnails, but request a cropped one.
        """
        self._test_thumbnail(
            "crop",
            None,
            expected_found=False,
            unable_to_thumbnail=self.test_image.unable_to_thumbnail,
        )

    @unittest.override_config(
        {"thumbnail_sizes": [{"width": 32, "height": 32, "method": "crop"}]}
    )
    def test_no_thumbnail_scale(self) -> None:
        """
        Override the config to generate only cropped thumbnails, but request a scaled one.
        """
        self._test_thumbnail(
            "scale",
            None,
            expected_found=False,
            unable_to_thumbnail=self.test_image.unable_to_thumbnail,
        )

    def test_thumbnail_repeated_thumbnail(self) -> None:
        """Test that fetching the same thumbnail works, and deleting the on disk
        thumbnail regenerates it.
        """
        self._test_thumbnail(
            "scale",
            self.test_image.expected_scaled,
            expected_found=self.test_image.expected_found,
            unable_to_thumbnail=self.test_image.unable_to_thumbnail,
        )

        if not self.test_image.expected_found:
            return

        # Fetching again should work, without re-requesting the image from the
        # remote.
        params = "?width=32&height=32&method=scale"
        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/thumbnail/{self.media_id}{params}",
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
        assert info is not None
        file_id = info.filesystem_id

        thumbnail_dir = self.media_repo.filepaths.remote_media_thumbnail_dir(
            origin, file_id
        )
        shutil.rmtree(thumbnail_dir, ignore_errors=True)

        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/thumbnail/{self.media_id}{params}",
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
        self,
        method: str,
        expected_body: Optional[bytes],
        expected_found: bool,
        unable_to_thumbnail: bool = False,
    ) -> None:
        """Test the given thumbnailing method works as expected.

        Args:
            method: The thumbnailing method to use (crop, scale).
            expected_body: The expected bytes from thumbnailing, or None if
                test should just check for a valid image.
            expected_found: True if the file should exist on the server, or False if
                a 404/400 is expected.
            unable_to_thumbnail: True if we expect the thumbnailing to fail (400), or
                False if the thumbnailing should succeed or a normal 404 is expected.
        """

        params = "?width=32&height=32&method=" + method
        channel = self.make_request(
            "GET",
            f"/_matrix/media/r0/thumbnail/{self.media_id}{params}",
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
        elif unable_to_thumbnail:
            # A 400 with a JSON body.
            self.assertEqual(channel.code, 400)
            self.assertEqual(
                channel.json_body,
                {
                    "errcode": "M_UNKNOWN",
                    "error": "Cannot find any thumbnails for the requested media ('/_matrix/media/r0/thumbnail/example.com/12345'). This might mean the media is not a supported_media_format=(image/jpeg, image/jpg, image/webp, image/gif, image/png) or that thumbnailing failed for some other reason. (Dynamic thumbnails are disabled on this server.)",
                },
            )
        else:
            # A 404 with a JSON body.
            self.assertEqual(channel.code, 404)
            self.assertEqual(
                channel.json_body,
                {
                    "errcode": "M_NOT_FOUND",
                    "error": "Not found '/_matrix/media/r0/thumbnail/example.com/12345'",
                },
            )

    @parameterized.expand([("crop", 16), ("crop", 64), ("scale", 16), ("scale", 64)])
    def test_same_quality(self, method: str, desired_size: int) -> None:
        """Test that choosing between thumbnails with the same quality rating succeeds.

        We are not particular about which thumbnail is chosen."""

        content_type = self.test_image.content_type.decode()
        media_repo = self.hs.get_media_repository()
        thumbnail_resouce = ThumbnailResource(
            self.hs, media_repo, media_repo.media_storage
        )

        self.assertIsNotNone(
            thumbnail_resouce._select_thumbnail(
                desired_width=desired_size,
                desired_height=desired_size,
                desired_method=method,
                desired_type=content_type,
                # Provide two identical thumbnails which are guaranteed to have the same
                # quality rating.
                thumbnail_infos=[
                    ThumbnailInfo(
                        width=32,
                        height=32,
                        method=method,
                        type=content_type,
                        length=256,
                    ),
                    ThumbnailInfo(
                        width=32,
                        height=32,
                        method=method,
                        type=content_type,
                        length=256,
                    ),
                ],
                file_id=f"image{self.test_image.extension.decode()}",
                url_cache=False,
                server_name=None,
            )
        )

    def test_x_robots_tag_header(self) -> None:
        """
        Tests that the `X-Robots-Tag` header is present, which informs web crawlers
        to not index, archive, or follow links in media.
        """
        channel = self._req(b"attachment; filename=out" + self.test_image.extension)

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
        channel = self._req(b"attachment; filename=out" + self.test_image.extension)

        headers = channel.headers

        self.assertEqual(
            headers.getRawHeaders(b"Cross-Origin-Resource-Policy"),
            [b"cross-origin"],
        )

    def test_unknown_v3_endpoint(self) -> None:
        """
        If the v3 endpoint fails, try the r0 one.
        """
        channel = self.make_request(
            "GET",
            f"/_matrix/media/v3/download/{self.media_id}",
            shorthand=False,
            await_result=False,
        )
        self.pump()

        # We've made one fetch, to example.com, using the media URL, and asking
        # the other server not to do a remote fetch
        self.assertEqual(len(self.fetches), 1)
        self.assertEqual(self.fetches[0][1], "example.com")
        self.assertEqual(
            self.fetches[0][2], "/_matrix/media/v3/download/" + self.media_id
        )

        # The result which says the endpoint is unknown.
        unknown_endpoint = b'{"errcode":"M_UNRECOGNIZED","error":"Unknown request"}'
        self.fetches[0][0].errback(
            HttpResponseException(404, "NOT FOUND", unknown_endpoint)
        )

        self.pump()

        # There should now be another request to the r0 URL.
        self.assertEqual(len(self.fetches), 2)
        self.assertEqual(self.fetches[1][1], "example.com")
        self.assertEqual(
            self.fetches[1][2], f"/_matrix/media/r0/download/{self.media_id}"
        )

        headers = {
            b"Content-Length": [b"%d" % (len(self.test_image.data))],
        }

        self.fetches[1][0].callback(
            (self.test_image.data, (len(self.test_image.data), headers))
        )

        self.pump()
        self.assertEqual(channel.code, 200)


class TestSpamCheckerLegacy:
    """A spam checker module that rejects all media that includes the bytes
    `evil`.

    Uses the legacy Spam-Checker API.
    """

    def __init__(self, config: Dict[str, Any], api: ModuleApi) -> None:
        self.config = config
        self.api = api

    @staticmethod
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

        load_legacy_spam_checkers(hs)

    def create_resource_dict(self) -> Dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

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
        self.helper.upload_media(SMALL_PNG, tok=self.tok, expect_code=200)

    def test_upload_ban(self) -> None:
        """Attempt to upload some data that includes bytes "evil", which should
        get rejected by the spam checker.
        """

        data = b"Some evil data"

        self.helper.upload_media(data, tok=self.tok, expect_code=400)


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

        hs.get_module_api().register_spam_checker_callbacks(
            check_media_file_for_spam=self.check_media_file_for_spam
        )

    def create_resource_dict(self) -> Dict[str, Resource]:
        resources = super().create_resource_dict()
        resources["/_matrix/media"] = self.hs.get_media_repository_resource()
        return resources

    async def check_media_file_for_spam(
        self, file_wrapper: ReadableFileWrapper, file_info: FileInfo
    ) -> Union[Codes, Literal["NOT_SPAM"], Tuple[Codes, JsonDict]]:
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
        self.helper.upload_media(SMALL_PNG, tok=self.tok, expect_code=200)

    def test_upload_ban(self) -> None:
        """Attempt to upload some data that includes bytes "evil", which should
        get rejected by the spam checker.
        """

        self.helper.upload_media(EVIL_DATA, tok=self.tok, expect_code=400)

        self.helper.upload_media(
            EVIL_DATA_EXPERIMENT,
            tok=self.tok,
            expect_code=400,
        )
