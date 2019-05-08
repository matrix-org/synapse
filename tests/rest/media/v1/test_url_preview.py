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

import attr
from netaddr import IPSet

from twisted.internet._resolver import HostResolution
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.error import DNSLookupError
from twisted.python.failure import Failure
from twisted.test.proto_helpers import AccumulatingProtocol
from twisted.web._newclient import ResponseDone

from synapse.config.repository import MediaStorageProviderConfig
from synapse.util.module_loader import load_module

from tests import unittest
from tests.server import FakeTransport


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
        config.url_preview_ip_range_blacklist = IPSet(
            (
                "192.168.1.1",
                "1.0.0.0/8",
                "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "2001:800::/21",
            )
        )
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
                    resolutionReceiver.addressResolved(i[0]('TCP', i[1], portNumber))
                resolutionReceiver.resolutionComplete()
                return resolutionReceiver

        self.reactor.nameResolver = Resolver()

    def test_cache_returns_correct_type(self):
        self.lookups["matrix.org"] = [(IPv4Address, "8.8.8.8")]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)
        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))
        client.dataReceived(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n"
            % (len(self.end_content),)
            + self.end_content
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

        # Check the cache returns the correct response
        request, channel = self.make_request(
            "GET", "url_preview?url=http://matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # Check the cache response has the same content
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

        # Clear the in-memory cache
        self.assertIn("http://matrix.org", self.preview_url._cache)
        self.preview_url._cache.pop("http://matrix.org")
        self.assertNotIn("http://matrix.org", self.preview_url._cache)

        # Check the database cache returns the correct response
        request, channel = self.make_request(
            "GET", "url_preview?url=http://matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # Check the cache response has the same content
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

    def test_non_ascii_preview_httpequiv(self):
        self.lookups["matrix.org"] = [(IPv4Address, "8.8.8.8")]

        end_content = (
            b'<html><head>'
            b'<meta http-equiv="Content-Type" content="text/html; charset=windows-1251"/>'
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
            b'<meta property="og:description" content="hi" />'
            b'</head></html>'
        )

        request, channel = self.make_request(
            "GET", "url_preview?url=http://matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)
        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))
        client.dataReceived(
            (
                b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                b"Content-Type: text/html; charset=\"utf8\"\r\n\r\n"
            )
            % (len(end_content),)
            + end_content
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], u"\u0434\u043a\u0430")

    def test_non_ascii_preview_content_type(self):
        self.lookups["matrix.org"] = [(IPv4Address, "8.8.8.8")]

        end_content = (
            b'<html><head>'
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
            b'<meta property="og:description" content="hi" />'
            b'</head></html>'
        )

        request, channel = self.make_request(
            "GET", "url_preview?url=http://matrix.org", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)
        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))
        client.dataReceived(
            (
                b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                b"Content-Type: text/html; charset=\"windows-1251\"\r\n\r\n"
            )
            % (len(end_content),)
            + end_content
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], u"\u0434\u043a\u0430")

    def test_ipaddr(self):
        """
        IP addresses can be previewed directly.
        """
        self.lookups["example.com"] = [(IPv4Address, "8.8.8.8")]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)
        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))
        client.dataReceived(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n"
            % (len(self.end_content),)
            + self.end_content
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

    def test_blacklisted_ip_specific(self):
        """
        Blacklisted IP addresses, found via DNS, are not spidered.
        """
        self.lookups["example.com"] = [(IPv4Address, "192.168.1.1")]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # No requests made.
        self.assertEqual(len(self.reactor.tcpClients), 0)
        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'DNS resolution failure during URL preview generation',
            },
        )

    def test_blacklisted_ip_range(self):
        """
        Blacklisted IP ranges, IPs found over DNS, are not spidered.
        """
        self.lookups["example.com"] = [(IPv4Address, "1.1.1.2")]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'DNS resolution failure during URL preview generation',
            },
        )

    def test_blacklisted_ip_specific_direct(self):
        """
        Blacklisted IP addresses, accessed directly, are not spidered.
        """
        request, channel = self.make_request(
            "GET", "url_preview?url=http://192.168.1.1", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # No requests made.
        self.assertEqual(len(self.reactor.tcpClients), 0)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'IP address blocked by IP blacklist entry',
            },
        )
        self.assertEqual(channel.code, 403)

    def test_blacklisted_ip_range_direct(self):
        """
        Blacklisted IP ranges, accessed directly, are not spidered.
        """
        request, channel = self.make_request(
            "GET", "url_preview?url=http://1.1.1.2", shorthand=False
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
        self.lookups["example.com"] = [(IPv4Address, "1.1.1.1")]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)

        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))

        client.dataReceived(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n"
            % (len(self.end_content),)
            + self.end_content
        )

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
        # Hardcode the URL resolving to the IP we want.
        self.lookups[u"example.com"] = [
            (IPv4Address, "1.1.1.2"),
            (IPv4Address, "8.8.8.8"),
        ]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()
        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'DNS resolution failure during URL preview generation',
            },
        )

    def test_blacklisted_ipv6_specific(self):
        """
        Blacklisted IP addresses, found via DNS, are not spidered.
        """
        self.lookups["example.com"] = [
            (IPv6Address, "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        ]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        # No requests made.
        self.assertEqual(len(self.reactor.tcpClients), 0)
        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'DNS resolution failure during URL preview generation',
            },
        )

    def test_blacklisted_ipv6_range(self):
        """
        Blacklisted IP ranges, IPs found over DNS, are not spidered.
        """
        self.lookups["example.com"] = [(IPv6Address, "2001:800::1")]

        request, channel = self.make_request(
            "GET", "url_preview?url=http://example.com", shorthand=False
        )
        request.render(self.preview_url)
        self.pump()

        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                'errcode': 'M_UNKNOWN',
                'error': 'DNS resolution failure during URL preview generation',
            },
        )
