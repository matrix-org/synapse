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

from mock import Mock

from twisted.internet.defer import Deferred

from synapse.config.repository import MediaStorageProviderConfig
from synapse.util.module_loader import load_module

from tests import unittest

import os
import shutil
import tempfile

from mock import Mock

from twisted.internet import defer, reactor

from synapse.rest.media.v1._base import FileInfo
from synapse.rest.media.v1.filepath import MediaFilePaths
from synapse.rest.media.v1.media_storage import MediaStorage
from synapse.rest.media.v1.storage_provider import FileStorageProviderBackend

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

        def get_file(url, output_stream, max_size):
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
            self.fetches.append((d, url))
            return d

        client = Mock()
        client.get_file = get_file

        self.storage_path = self.mktemp()
        os.mkdir(self.storage_path)

        config = self.default_config()
        config.media_store_path = self.storage_path

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
        self.download_resource = self.media_repo.children[b'download_resource']

    def test_get_remote_media(self):

        request, channel = self.make_request(
            "GET", "download/example.com/12345", shorthand=False
        )
        request.render(self.download_resource)
        self.pump()

        # We've made one fetch
        self.assertEqual(len(self.fetches), 1)

        end_content = (
            b'<html><head>'
            b'<meta property="og:title" content="~matrix~" />'
            b'<meta property="og:description" content="hi" />'
            b'</head></html>'
        )

        self.fetches[0][0].callback(
            (
                end_content,
                (
                    len(end_content),
                    {
                        b"Content-Length": [b"%d" % (len(end_content))],
                        b"Content-Type": [b'text/html; charset="utf8"'],
                    },
                    "https://example.com",
                    200,
                ),
            )
        )

        self.pump()
        self.assertEqual(channel.code, 200)

        print(request)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

        # Check the cache returns the correct response
        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # Only one fetch, still, since we'll lean on the cache
        self.assertEqual(len(self.fetches), 1)

        # Check the cache response has the same content
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

        # Clear the in-memory cache
        self.assertIn("matrix.org", self.preview_url._cache)
        self.preview_url._cache.pop("matrix.org")
        self.assertNotIn("matrix.org", self.preview_url._cache)

        # Check the database cache returns the correct response
        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # Only one fetch, still, since we'll lean on the cache
        self.assertEqual(len(self.fetches), 1)

        # Check the cache response has the same content
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )
