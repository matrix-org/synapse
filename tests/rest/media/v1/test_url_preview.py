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

from netaddr import IPSet

from twisted.internet.defer import Deferred, succeed
from twisted.web.http_headers import Headers

from synapse.config.repository import MediaStorageProviderConfig
from synapse.util.logcontext import make_deferred_yieldable
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
        config.url_preview_ip_range_blacklist = IPSet(("192.168.1.1", "1.0.0.0/8"))
        config.url_preview_ip_range_whitelist = IPSet(("1.1.1.1",))
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
            return make_deferred_yieldable(d)

        client = Mock()
        client.get_file = get_file

        self.media_repo = hs.get_media_repository_resource()
        preview_url = self.media_repo.children[b'preview_url']
        self._old_client = preview_url.client
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

    def test_non_ascii_preview_httpequiv(self):

        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # We've made one fetch
        self.assertEqual(len(self.fetches), 1)

        end_content = (
            b'<html><head>'
            b'<meta http-equiv="Content-Type" content="text/html; charset=windows-1251"/>'
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
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
                        # This charset=utf-8 should be ignored, because the
                        # document has a meta tag overriding it.
                        b"Content-Type": [b'text/html; charset="utf8"'],
                    },
                    "https://example.com",
                    200,
                ),
            )
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], u"\u0434\u043a\u0430")

    def test_non_ascii_preview_content_type(self):

        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # We've made one fetch
        self.assertEqual(len(self.fetches), 1)

        end_content = (
            b'<html><head>'
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
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
                        b"Content-Type": [b'text/html; charset="windows-1251"'],
                    },
                    "https://example.com",
                    200,
                ),
            )
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], u"\u0434\u043a\u0430")

    def make_response(self, body, headers):

        # Assemble a mocked out response
        def deliver(to):
            to.dataReceived(body)
            to.connectionLost(Mock())

        res = Mock()
        res.code = 200
        res.headers = Headers(headers)
        res.deliverBody = deliver

        return res

    def test_ipaddr(self):
        """
        IP addresses can be previewed directly.
        """
        # Mock out Treq to one we control
        treq = Mock()
        d = Deferred()
        treq.request = Mock(return_value=d)
        self.preview_url.client = self._old_client
        self.preview_url.client._treq = treq

        # Hardcode the URL resolving to the IP we want
        self.reactor.resolve = lambda x: succeed("8.8.8.8")

        request, channel = self.make_request(
            "GET", "url_preview?url=http://8.8.8.8", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        self.assertEqual(treq.request.call_count, 1)

        end_content = (
            b'<html><head>'
            b'<meta property="og:title" content="~matrix~" />'
            b'<meta property="og:description" content="hi" />'
            b'</head></html>'
        )

        # Build and deliver the mocked out response.
        res = self.make_response(end_content, {b"Content-Type": [b"text/html"]})
        d.callback(res)

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

    def test_blacklisted_ip_specific(self):
        """
        Blacklisted IP addresses are not spidered.
        """
        # Mock out Treq to one we control
        treq = Mock()
        d = Deferred()
        treq.request = Mock(return_value=d)
        self.preview_url.client = self._old_client
        self.preview_url.client._treq = treq

        # Hardcode the URL resolving to the IP we want
        self.reactor.resolve = lambda x: succeed("192.168.1.1")

        request, channel = self.make_request(
            "GET", "url_preview?url=http://192.168.1.1", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # Treq is NOT called, because it will be blacklisted
        self.assertEqual(treq.request.call_count, 0)
        self.assertEqual(channel.code, 403)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'IP address blocked by IP blacklist entry',
            },
        )

    def test_blacklisted_ip_range(self):
        """
        Blacklisted IP ranges are not spidered.
        """
        # Mock out Treq to one we control
        treq = Mock()
        d = Deferred()
        treq.request = Mock(return_value=d)
        self.preview_url.client = self._old_client
        self.preview_url.client._treq = treq

        # Hardcode the URL resolving to the IP we want
        self.reactor.resolve = lambda x: succeed("1.1.1.2")

        request, channel = self.make_request(
            "GET", "url_preview?url=http://1.1.1.2", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # Treq is NOT called, because it will be blacklisted
        self.assertEqual(treq.request.call_count, 0)
        self.assertEqual(channel.code, 403)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'IP address blocked by IP blacklist entry',
            },
        )


    def test_blacklisted_ip_range_whitelisted_ip(self):
        """
        Blacklisted but then subsequently whitelisted IP addresses can be
        spidered.
        """
        # Mock out Treq to one we control
        treq = Mock()
        d = Deferred()
        treq.request = Mock(return_value=d)
        self.preview_url.client = self._old_client
        self.preview_url.client._treq = treq

        # Hardcode the URL resolving to the IP we want. This is an IP that is
        # caught by a blacklist range, but is then subsequently whitelisted.
        self.reactor.resolve = lambda x: succeed("1.1.1.1")

        request, channel = self.make_request(
            "GET", "url_preview?url=http://1.1.1.1", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        self.assertEqual(treq.request.call_count, 1)

        end_content = (
            b'<html><head>'
            b'<meta property="og:title" content="~matrix~" />'
            b'<meta property="og:description" content="hi" />'
            b'</head></html>'
        )

        # Build and deliver the mocked out response.
        res = self.make_response(end_content, {b"Content-Type": [b"text/html"]})
        d.callback(res)

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )
