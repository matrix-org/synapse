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
import json
import os
import re

from mock import patch

from twisted.internet._resolver import HostResolution
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.error import DNSLookupError
from twisted.test.proto_helpers import AccumulatingProtocol

from tests import unittest
from tests.server import FakeTransport

try:
    import lxml
except ImportError:
    lxml = None


class URLPreviewTests(unittest.HomeserverTestCase):
    if not lxml:
        skip = "url preview feature requires lxml"

    hijack_auth = True
    user_id = "@test:user"
    end_content = (
        b"<html><head>"
        b'<meta property="og:title" content="~matrix~" />'
        b'<meta property="og:description" content="hi" />'
        b"</head></html>"
    )

    def make_homeserver(self, reactor, clock):

        config = self.default_config()
        config["url_preview_enabled"] = True
        config["max_spider_size"] = 9999999
        config["url_preview_ip_range_blacklist"] = (
            "192.168.1.1",
            "1.0.0.0/8",
            "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:800::/21",
        )
        config["url_preview_ip_range_whitelist"] = ("1.1.1.1",)
        config["url_preview_url_blacklist"] = []
        config["url_preview_accept_language"] = [
            "en-UK",
            "en-US;q=0.9",
            "fr;q=0.8",
            "*;q=0.7",
        ]

        self.storage_path = self.mktemp()
        self.media_store_path = self.mktemp()
        os.mkdir(self.storage_path)
        os.mkdir(self.media_store_path)
        config["media_store_path"] = self.media_store_path

        provider_config = {
            "module": "synapse.rest.media.v1.storage_provider.FileStorageProviderBackend",
            "store_local": True,
            "store_synchronous": False,
            "store_remote": True,
            "config": {"directory": self.storage_path},
        }

        config["media_storage_providers"] = [provider_config]

        hs = self.setup_test_homeserver(config=config)

        return hs

    def prepare(self, reactor, clock, hs):

        self.media_repo = hs.get_media_repository_resource()
        self.preview_url = self.media_repo.children[b"preview_url"]

        self.lookups = {}

        class Resolver:
            def resolveHostName(
                _self,
                resolutionReceiver,
                hostName,
                portNumber=0,
                addressTypes=None,
                transportSemantics="TCP",
            ):

                resolution = HostResolution(hostName)
                resolutionReceiver.resolutionBegan(resolution)
                if hostName not in self.lookups:
                    raise DNSLookupError("OH NO")

                for i in self.lookups[hostName]:
                    resolutionReceiver.addressResolved(i[0]("TCP", i[1], portNumber))
                resolutionReceiver.resolutionComplete()
                return resolutionReceiver

        self.reactor.nameResolver = Resolver()

    def create_test_resource(self):
        return self.hs.get_media_repository_resource()

    def test_cache_returns_correct_type(self):
        self.lookups["matrix.org"] = [(IPv4Address, "10.1.2.3")]

        channel = self.make_request(
            "GET",
            "preview_url?url=http://matrix.org",
            shorthand=False,
            await_result=False,
        )
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
        channel = self.make_request(
            "GET", "preview_url?url=http://matrix.org", shorthand=False
        )

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
        channel = self.make_request(
            "GET", "preview_url?url=http://matrix.org", shorthand=False
        )

        # Check the cache response has the same content
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

    def test_non_ascii_preview_httpequiv(self):
        self.lookups["matrix.org"] = [(IPv4Address, "10.1.2.3")]

        end_content = (
            b"<html><head>"
            b'<meta http-equiv="Content-Type" content="text/html; charset=windows-1251"/>'
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
            b'<meta property="og:description" content="hi" />'
            b"</head></html>"
        )

        channel = self.make_request(
            "GET",
            "preview_url?url=http://matrix.org",
            shorthand=False,
            await_result=False,
        )
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)
        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))
        client.dataReceived(
            (
                b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                b'Content-Type: text/html; charset="utf8"\r\n\r\n'
            )
            % (len(end_content),)
            + end_content
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], "\u0434\u043a\u0430")

    def test_non_ascii_preview_content_type(self):
        self.lookups["matrix.org"] = [(IPv4Address, "10.1.2.3")]

        end_content = (
            b"<html><head>"
            b'<meta property="og:title" content="\xe4\xea\xe0" />'
            b'<meta property="og:description" content="hi" />'
            b"</head></html>"
        )

        channel = self.make_request(
            "GET",
            "preview_url?url=http://matrix.org",
            shorthand=False,
            await_result=False,
        )
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)
        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))
        client.dataReceived(
            (
                b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                b'Content-Type: text/html; charset="windows-1251"\r\n\r\n'
            )
            % (len(end_content),)
            + end_content
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["og:title"], "\u0434\u043a\u0430")

    def test_overlong_title(self):
        self.lookups["matrix.org"] = [(IPv4Address, "10.1.2.3")]

        end_content = (
            b"<html><head>"
            b"<title>" + b"x" * 2000 + b"</title>"
            b'<meta property="og:description" content="hi" />'
            b"</head></html>"
        )

        channel = self.make_request(
            "GET",
            "preview_url?url=http://matrix.org",
            shorthand=False,
            await_result=False,
        )
        self.pump()

        client = self.reactor.tcpClients[0][2].buildProtocol(None)
        server = AccumulatingProtocol()
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))
        client.dataReceived(
            (
                b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                b'Content-Type: text/html; charset="windows-1251"\r\n\r\n'
            )
            % (len(end_content),)
            + end_content
        )

        self.pump()
        self.assertEqual(channel.code, 200)
        res = channel.json_body
        # We should only see the `og:description` field, as `title` is too long and should be stripped out
        self.assertCountEqual(["og:description"], res.keys())

    def test_ipaddr(self):
        """
        IP addresses can be previewed directly.
        """
        self.lookups["example.com"] = [(IPv4Address, "10.1.2.3")]

        channel = self.make_request(
            "GET",
            "preview_url?url=http://example.com",
            shorthand=False,
            await_result=False,
        )
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

        channel = self.make_request(
            "GET", "preview_url?url=http://example.com", shorthand=False
        )

        # No requests made.
        self.assertEqual(len(self.reactor.tcpClients), 0)
        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "DNS resolution failure during URL preview generation",
            },
        )

    def test_blacklisted_ip_range(self):
        """
        Blacklisted IP ranges, IPs found over DNS, are not spidered.
        """
        self.lookups["example.com"] = [(IPv4Address, "1.1.1.2")]

        channel = self.make_request(
            "GET", "preview_url?url=http://example.com", shorthand=False
        )

        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "DNS resolution failure during URL preview generation",
            },
        )

    def test_blacklisted_ip_specific_direct(self):
        """
        Blacklisted IP addresses, accessed directly, are not spidered.
        """
        channel = self.make_request(
            "GET", "preview_url?url=http://192.168.1.1", shorthand=False
        )

        # No requests made.
        self.assertEqual(len(self.reactor.tcpClients), 0)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "IP address blocked by IP blacklist entry",
            },
        )
        self.assertEqual(channel.code, 403)

    def test_blacklisted_ip_range_direct(self):
        """
        Blacklisted IP ranges, accessed directly, are not spidered.
        """
        channel = self.make_request(
            "GET", "preview_url?url=http://1.1.1.2", shorthand=False
        )

        self.assertEqual(channel.code, 403)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "IP address blocked by IP blacklist entry",
            },
        )

    def test_blacklisted_ip_range_whitelisted_ip(self):
        """
        Blacklisted but then subsequently whitelisted IP addresses can be
        spidered.
        """
        self.lookups["example.com"] = [(IPv4Address, "1.1.1.1")]

        channel = self.make_request(
            "GET",
            "preview_url?url=http://example.com",
            shorthand=False,
            await_result=False,
        )
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
        self.lookups["example.com"] = [
            (IPv4Address, "1.1.1.2"),
            (IPv4Address, "10.1.2.3"),
        ]

        channel = self.make_request(
            "GET", "preview_url?url=http://example.com", shorthand=False
        )
        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "DNS resolution failure during URL preview generation",
            },
        )

    def test_blacklisted_ipv6_specific(self):
        """
        Blacklisted IP addresses, found via DNS, are not spidered.
        """
        self.lookups["example.com"] = [
            (IPv6Address, "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        ]

        channel = self.make_request(
            "GET", "preview_url?url=http://example.com", shorthand=False
        )

        # No requests made.
        self.assertEqual(len(self.reactor.tcpClients), 0)
        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "DNS resolution failure during URL preview generation",
            },
        )

    def test_blacklisted_ipv6_range(self):
        """
        Blacklisted IP ranges, IPs found over DNS, are not spidered.
        """
        self.lookups["example.com"] = [(IPv6Address, "2001:800::1")]

        channel = self.make_request(
            "GET", "preview_url?url=http://example.com", shorthand=False
        )

        self.assertEqual(channel.code, 502)
        self.assertEqual(
            channel.json_body,
            {
                "errcode": "M_UNKNOWN",
                "error": "DNS resolution failure during URL preview generation",
            },
        )

    def test_OPTIONS(self):
        """
        OPTIONS returns the OPTIONS.
        """
        channel = self.make_request(
            "OPTIONS", "preview_url?url=http://example.com", shorthand=False
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body, {})

    def test_accept_language_config_option(self):
        """
        Accept-Language header is sent to the remote server
        """
        self.lookups["example.com"] = [(IPv4Address, "10.1.2.3")]

        # Build and make a request to the server
        channel = self.make_request(
            "GET",
            "preview_url?url=http://example.com",
            shorthand=False,
            await_result=False,
        )
        self.pump()

        # Extract Synapse's tcp client
        client = self.reactor.tcpClients[0][2].buildProtocol(None)

        # Build a fake remote server to reply with
        server = AccumulatingProtocol()

        # Connect the two together
        server.makeConnection(FakeTransport(client, self.reactor))
        client.makeConnection(FakeTransport(server, self.reactor))

        # Tell Synapse that it has received some data from the remote server
        client.dataReceived(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n"
            % (len(self.end_content),)
            + self.end_content
        )

        # Move the reactor along until we get a response on our original channel
        self.pump()
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body, {"og:title": "~matrix~", "og:description": "hi"}
        )

        # Check that the server received the Accept-Language header as part
        # of the request from Synapse
        self.assertIn(
            (
                b"Accept-Language: en-UK\r\n"
                b"Accept-Language: en-US;q=0.9\r\n"
                b"Accept-Language: fr;q=0.8\r\n"
                b"Accept-Language: *;q=0.7"
            ),
            server.data,
        )

    def test_oembed_photo(self):
        """Test an oEmbed endpoint which returns a 'photo' type which redirects the preview to a new URL."""
        # Route the HTTP version to an HTTP endpoint so that the tests work.
        with patch.dict(
            "synapse.rest.media.v1.preview_url_resource._oembed_patterns",
            {
                re.compile(
                    r"http://twitter\.com/.+/status/.+"
                ): "http://publish.twitter.com/oembed",
            },
            clear=True,
        ):

            self.lookups["publish.twitter.com"] = [(IPv4Address, "10.1.2.3")]
            self.lookups["cdn.twitter.com"] = [(IPv4Address, "10.1.2.3")]

            result = {
                "version": "1.0",
                "type": "photo",
                "url": "http://cdn.twitter.com/matrixdotorg",
            }
            oembed_content = json.dumps(result).encode("utf-8")

            end_content = (
                b"<html><head>"
                b"<title>Some Title</title>"
                b'<meta property="og:description" content="hi" />'
                b"</head></html>"
            )

            channel = self.make_request(
                "GET",
                "preview_url?url=http://twitter.com/matrixdotorg/status/12345",
                shorthand=False,
                await_result=False,
            )
            self.pump()

            client = self.reactor.tcpClients[0][2].buildProtocol(None)
            server = AccumulatingProtocol()
            server.makeConnection(FakeTransport(client, self.reactor))
            client.makeConnection(FakeTransport(server, self.reactor))
            client.dataReceived(
                (
                    b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                    b'Content-Type: application/json; charset="utf8"\r\n\r\n'
                )
                % (len(oembed_content),)
                + oembed_content
            )

            self.pump()

            client = self.reactor.tcpClients[1][2].buildProtocol(None)
            server = AccumulatingProtocol()
            server.makeConnection(FakeTransport(client, self.reactor))
            client.makeConnection(FakeTransport(server, self.reactor))
            client.dataReceived(
                (
                    b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                    b'Content-Type: text/html; charset="utf8"\r\n\r\n'
                )
                % (len(end_content),)
                + end_content
            )

            self.pump()

            self.assertEqual(channel.code, 200)
            self.assertEqual(
                channel.json_body, {"og:title": "Some Title", "og:description": "hi"}
            )

    def test_oembed_rich(self):
        """Test an oEmbed endpoint which returns HTML content via the 'rich' type."""
        # Route the HTTP version to an HTTP endpoint so that the tests work.
        with patch.dict(
            "synapse.rest.media.v1.preview_url_resource._oembed_patterns",
            {
                re.compile(
                    r"http://twitter\.com/.+/status/.+"
                ): "http://publish.twitter.com/oembed",
            },
            clear=True,
        ):

            self.lookups["publish.twitter.com"] = [(IPv4Address, "10.1.2.3")]

            result = {
                "version": "1.0",
                "type": "rich",
                "html": "<div>Content Preview</div>",
            }
            end_content = json.dumps(result).encode("utf-8")

            channel = self.make_request(
                "GET",
                "preview_url?url=http://twitter.com/matrixdotorg/status/12345",
                shorthand=False,
                await_result=False,
            )
            self.pump()

            client = self.reactor.tcpClients[0][2].buildProtocol(None)
            server = AccumulatingProtocol()
            server.makeConnection(FakeTransport(client, self.reactor))
            client.makeConnection(FakeTransport(server, self.reactor))
            client.dataReceived(
                (
                    b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                    b'Content-Type: application/json; charset="utf8"\r\n\r\n'
                )
                % (len(end_content),)
                + end_content
            )

            self.pump()
            self.assertEqual(channel.code, 200)
            self.assertEqual(
                channel.json_body,
                {"og:title": None, "og:description": "Content Preview"},
            )
