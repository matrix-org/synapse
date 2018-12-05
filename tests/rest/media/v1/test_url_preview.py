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
import attr

from twisted.web._newclient import ResponseDone
from twisted.internet.defer import Deferred, succeed
from twisted.internet._resolver import HostResolution
from twisted.internet.address import IPv4Address
from twisted.internet.defer import Deferred
from twisted.internet.error import DNSLookupError
from twisted.web.http_headers import Headers
from twisted.web.client import Response
from twisted.python.failure import Failure

from synapse.config.repository import MediaStorageProviderConfig
from synapse.util.logcontext import make_deferred_yieldable
from synapse.util.module_loader import load_module

from tests import unittest


@attr.s
class FakeResponse(object):
    version = attr.ib()
    code = attr.ib()
    phrase = attr.ib()
    headers = attr.ib()
    body = attr.ib()
    absoluteURI = attr.ib()

    @property
    def request(self):
        @attr.s
        class FakeTransport(object):
            absoluteURI = self.absoluteURI

        return FakeTransport()

    def deliverBody(self, protocol):
        protocol.dataReceived(self.body)
        protocol.connectionLost(Failure(ResponseDone()))


class URLPreviewTests(unittest.HomeserverTestCase):

    hijack_auth = True
    user_id = "@test:user"
    end_content = (
        b'<html><head>'
        b'<meta property="og:title" content="~matrix~" />'
        b'<meta property="og:description" content="hi" />'
        b'</head></html>'
    )

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

        self.media_repo = hs.get_media_repository_resource()
        self.preview_url = self.media_repo.children[b'preview_url']

        class Agent(object):
            def request(_self, *args, **kwargs):
                return self._on_request(*args, **kwargs)

        # Load in the Agent we want
        self.preview_url.client._make_agent(Agent())

        self.lookups = {}

        class Resolver(object):
            def resolveHostName(
                _self,
                resolutionReceiver,
                hostName,
                portNumber=0,
                addressTypes=None,
                transportSemantics='TCP',
            ):

                resolution = HostResolution(hostName)
                resolutionReceiver.resolutionBegan(resolution)
                if hostName not in self.lookups:
                    raise DNSLookupError("OH NO")

                for i in self.lookups[hostName]:
                    resolutionReceiver.addressResolved(
                        i[0]('TCP', i[1], portNumber)
                    )
                resolutionReceiver.resolutionComplete()
                return resolutionReceiver

        self.reactor.nameResolver = Resolver()

    def test_cache_returns_correct_type(self):

        calls = [0]

        def _on_request(method, uri, headers=None, bodyProducer=None):

            calls[0] += 1
            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(self.end_content))],
                    b"Content-Type": [b'text/html; charset="utf8"'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, self.end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

    def test_cache_returns_correct_type(self):

        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

        self.assertEqual(calls[0], 1)

        # Check the cache returns the correct response
        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # Only one fetch, still, since we'll lean on the cache
        self.assertEqual(calls[0], 1)

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
        self.assertEqual(calls[0], 1)

        # Check the cache response has the same content
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

    def test_non_ascii_preview_httpequiv(self):

        end_content = (
            b'<html><head>'
            b'<meta http-equiv="Content-Type" content="text/html; charset=windows-1251"/>'
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
            b'<meta property="og:description" content="hi" />'
            b'</head></html>'
        )

        def _on_request(method, uri, headers=None, bodyProducer=None):

            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(end_content))],
                    # This charset=utf-8 should be ignored, because the
                    # document has a meta tag overriding it.
                    b"Content-Type": [b'text/html; charset="utf8"'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], u"\u0434\u043a\u0430")

    def test_non_ascii_preview_content_type(self):

        end_content = (
            b'<html><head>'
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
            b'<meta property="og:description" content="hi" />'
            b'</head></html>'
        )

        def _on_request(method, uri, headers=None, bodyProducer=None):

            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(end_content))],
                    b"Content-Type": [b'text/html; charset="windows-1251"'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

        request, channel = self.make_request(
            "GET", "url_preview?url=matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], u"\u0434\u043a\u0430")

    def test_ipaddr(self):
        """
        IP addresses can be previewed directly.
        """

        def _on_request(method, uri, headers=None, bodyProducer=None):

            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(self.end_content))],
                    b"Content-Type": [b'text/html'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, self.end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

    def test_blacklisted_ip_specific(self):
        """
        Blacklisted IP addresses are not spidered.
        """

        def _on_request(method, uri, headers=None, bodyProducer=None):

            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(self.end_content))],
                    b"Content-Type": [b'text/html'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, self.end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()
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

        def _on_request(method, uri, headers=None, bodyProducer=None):

            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(self.end_content))],
                    b"Content-Type": [b'text/html'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, self.end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

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
        def _on_request(method, uri, headers=None, bodyProducer=None):

            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(self.end_content))],
                    b"Content-Type": [b'text/html'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, self.end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

    def test_blacklisted_ip_with_external_ip(self):
        """
        If a hostname resolves a blacklisted IP, even if there's a
        non-blacklisted one, it will be rejected.
        """
        def _on_request(method, uri, headers=None, bodyProducer=None):

            h = Headers(
                {
                    b"Content-Length": [b"%d" % (len(self.end_content))],
                    b"Content-Type": [b'text/html'],
                }
            )
            resp = FakeResponse(b"1.1", 200, b"OK", h, self.end_content, uri)
            return succeed(resp)

        self._on_request = _on_request

        # Hardcode the URL resolving to the IP we want.
        self.lookups[u"example.com"] = ["1.1.1.2", "8.8.8.8"]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()
        self.assertEqual(channel.code, 403)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'IP address blocked by IP blacklist entry',
            },
        )
