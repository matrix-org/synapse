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


class URLPreviewTests(unittest.HomeserverTestCase):

    hijack_auth = True
    user_id = "@test:user"

    def make_homeserver(self, reactor, clock):

        self.storage_path = self.mktemp()
        os.mkdir(self.storage_path)

        config = self.default_config()
        config.url_preview_enabled = True
        config.max_spider_size = 9999999
        config.url_preview_url_blacklist = []
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

        hs = self.setup_test_homeserver(config=config)

        return hs

    def prepare(self, reactor, clock, hs):

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

        self.media_repo = hs.get_media_repository_resource()
        preview_url = self.media_repo.children[b'preview_url']
        preview_url.client = client
        self.preview_url = preview_url

    def test_cache_returns_correct_type(self):

        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
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
