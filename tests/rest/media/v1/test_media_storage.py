# -*- coding: utf-8 -*-
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


import os
import shutil
import tempfile
from binascii import unhexlify

from mock import Mock
from six.moves.urllib import parse

from twisted.internet import defer, reactor
from twisted.internet.defer import Deferred

from synapse.config.repository import MediaStorageProviderConfig
from synapse.rest.media.v1._base import FileInfo
from synapse.rest.media.v1.filepath import MediaFilePaths
from synapse.rest.media.v1.media_storage import MediaStorage
from synapse.rest.media.v1.storage_provider import FileStorageProviderBackend
from synapse.util.logcontext import make_deferred_yieldable
from synapse.util.module_loader import load_module

from tests import unittest


class MediaStorageTests(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="synapse-tests-")

        self.primary_base_path = os.path.join(self.test_dir, "primary")
        self.secondary_base_path = os.path.join(self.test_dir, "secondary")

        hs = Mock()
        hs.get_reactor = Mock(return_value=reactor)
        hs.config.media_store_path = self.primary_base_path

        storage_providers = [FileStorageProviderBackend(hs, self.secondary_base_path)]

        self.filepaths = MediaFilePaths(self.primary_base_path)
        self.media_storage = MediaStorage(
            hs, self.primary_base_path, self.filepaths, storage_providers
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @defer.inlineCallbacks
    def test_ensure_media_is_in_local_cache(self):
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
        local_path = yield self.media_storage.ensure_media_is_in_local_cache(file_info)

        self.assertTrue(os.path.exists(local_path))

        # Asserts the file is under the expected local cache directory
        self.assertEquals(
            os.path.commonprefix([self.primary_base_path, local_path]),
            self.primary_base_path,
        )

        with open(local_path) as f:
            body = f.read()

        self.assertEqual(test_body, body)


class MediaRepoTests(unittest.HomeserverTestCase):

    hijack_auth = True
    user_id = "@test:user"

    def make_homeserver(self, reactor, clock):

        self.fetches = []

        def get_file(destination, path, output_stream, args=None, max_size=None):
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
        os.mkdir(self.storage_path)

        config = self.default_config()
        config.media_store_path = self.storage_path
        config.thumbnail_requirements = {}
        config.max_image_pixels = 2000000

        provider_config = {
            "module": "synapse.rest.media.v1.storage_provider.FileStorageProviderBackend",
            "store_local": True,
            "store_synchronous": False,
            "store_remote": True,
            "config": {"directory": self.storage_path},
        }

        loaded = list(load_module(provider_config)) + [
            MediaStorageProviderConfig(False, False, False)
        ]

        config.media_storage_providers = [loaded]

        hs = self.setup_test_homeserver(config=config, http_client=client)

        return hs

    def prepare(self, reactor, clock, hs):

        self.media_repo = hs.get_media_repository_resource()
        self.download_resource = self.media_repo.children[b'download']

        # smol png
        self.end_content = unhexlify(
            b"89504e470d0a1a0a0000000d4948445200000001000000010806"
            b"0000001f15c4890000000a49444154789c63000100000500010d"
            b"0a2db40000000049454e44ae426082"
        )

    def _req(self, content_disposition):

        request, channel = self.make_request(
            "GET", "example.com/12345", shorthand=False
        )
        request.render(self.download_resource)
        self.pump()

        # We've made one fetch, to example.com, using the media URL, and asking
        # the other server not to do a remote fetch
        self.assertEqual(len(self.fetches), 1)
        self.assertEqual(self.fetches[0][1], "example.com")
        self.assertEqual(
            self.fetches[0][2], "/_matrix/media/v1/download/example.com/12345"
        )
        self.assertEqual(self.fetches[0][3], {"allow_remote": "false"})

        headers = {
            b"Content-Length": [b"%d" % (len(self.end_content))],
            b"Content-Type": [b'image/png'],
        }
        if content_disposition:
            headers[b"Content-Disposition"] = [content_disposition]

        self.fetches[0][0].callback(
            (self.end_content, (len(self.end_content), headers))
        )

        self.pump()
        self.assertEqual(channel.code, 200)

        return channel

    def test_disposition_filename_ascii(self):
        """
        If the filename is filename=<ascii> then Synapse will decode it as an
        ASCII string, and use filename= in the response.
        """
        channel = self._req(b"inline; filename=out.png")

        headers = channel.headers
        self.assertEqual(headers.getRawHeaders(b"Content-Type"), [b"image/png"])
        self.assertEqual(
            headers.getRawHeaders(b"Content-Disposition"), [b"inline; filename=out.png"]
        )

    def test_disposition_filenamestar_utf8escaped(self):
        """
        If the filename is filename=*utf8''<utf8 escaped> then Synapse will
        correctly decode it as the UTF-8 string, and use filename* in the
        response.
        """
        filename = parse.quote(u"\u2603".encode('utf8')).encode('ascii')
        channel = self._req(b"inline; filename*=utf-8''" + filename + b".png")

        headers = channel.headers
        self.assertEqual(headers.getRawHeaders(b"Content-Type"), [b"image/png"])
        self.assertEqual(
            headers.getRawHeaders(b"Content-Disposition"),
            [b"inline; filename*=utf-8''" + filename + b".png"],
        )

    def test_disposition_none(self):
        """
        If there is no filename, one isn't passed on in the Content-Disposition
        of the request.
        """
        channel = self._req(None)

        headers = channel.headers
        self.assertEqual(headers.getRawHeaders(b"Content-Type"), [b"image/png"])
        self.assertEqual(headers.getRawHeaders(b"Content-Disposition"), None)
