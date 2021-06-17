# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import logging
import os
from binascii import unhexlify
from typing import Optional, Tuple

from twisted.internet.protocol import Factory
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.web.http import HTTPChannel
from twisted.web.server import Request

from synapse.rest import admin
from synapse.rest.client.v1 import login
from synapse.server import HomeServer

from tests.http import TestServerTLSConnectionFactory, get_test_ca_cert_file
from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.server import FakeChannel, FakeSite, FakeTransport, make_request

logger = logging.getLogger(__name__)

test_server_connection_factory = None  # type: Optional[TestServerTLSConnectionFactory]


class MediaRepoShardTestCase(BaseMultiWorkerStreamTestCase):
    """Checks running multiple media repos work correctly."""

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.user_id = self.register_user("user", "pass")
        self.access_token = self.login("user", "pass")

        self.reactor.lookups["example.com"] = "1.2.3.4"

    def default_config(self):
        conf = super().default_config()
        conf["federation_custom_ca_list"] = [get_test_ca_cert_file()]
        return conf

    def _get_media_req(
        self, hs: HomeServer, target: str, media_id: str
    ) -> Tuple[FakeChannel, Request]:
        """Request some remote media from the given HS by calling the download
        API.

        This then triggers an outbound request from the HS to the target.

        Returns:
            The channel for the *client* request and the *outbound* request for
            the media which the caller should respond to.
        """
        resource = hs.get_media_repository_resource().children[b"download"]
        channel = make_request(
            self.reactor,
            FakeSite(resource),
            "GET",
            "/{}/{}".format(target, media_id),
            shorthand=False,
            access_token=self.access_token,
            await_result=False,
        )
        self.pump()

        clients = self.reactor.tcpClients
        self.assertGreaterEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients.pop()

        # build the test server
        server_tls_protocol = _build_test_server(get_connection_factory())

        # now, tell the client protocol factory to build the client protocol (it will be a
        # _WrappingProtocol, around a TLSMemoryBIOProtocol, around an
        # HTTP11ClientProtocol) and wire the output of said protocol up to the server via
        # a FakeTransport.
        #
        # Normally this would be done by the TCP socket code in Twisted, but we are
        # stubbing that out here.
        client_protocol = client_factory.buildProtocol(None)
        client_protocol.makeConnection(
            FakeTransport(server_tls_protocol, self.reactor, client_protocol)
        )

        # tell the server tls protocol to send its stuff back to the client, too
        server_tls_protocol.makeConnection(
            FakeTransport(client_protocol, self.reactor, server_tls_protocol)
        )

        # fish the test server back out of the server-side TLS protocol.
        http_server = server_tls_protocol.wrappedProtocol

        # give the reactor a pump to get the TLS juices flowing.
        self.reactor.pump((0.1,))

        self.assertEqual(len(http_server.requests), 1)
        request = http_server.requests[0]

        self.assertEqual(request.method, b"GET")
        self.assertEqual(
            request.path,
            "/_matrix/media/r0/download/{}/{}".format(target, media_id).encode("utf-8"),
        )
        self.assertEqual(
            request.requestHeaders.getRawHeaders(b"host"), [target.encode("utf-8")]
        )

        return channel, request

    def test_basic(self):
        """Test basic fetching of remote media from a single worker."""
        hs1 = self.make_worker_hs("synapse.app.generic_worker")

        channel, request = self._get_media_req(hs1, "example.com:443", "ABC123")

        request.setResponseCode(200)
        request.responseHeaders.setRawHeaders(b"Content-Type", [b"text/plain"])
        request.write(b"Hello!")
        request.finish()

        self.pump(0.1)

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.result["body"], b"Hello!")

    def test_download_simple_file_race(self):
        """Test that fetching remote media from two different processes at the
        same time works.
        """
        hs1 = self.make_worker_hs("synapse.app.generic_worker")
        hs2 = self.make_worker_hs("synapse.app.generic_worker")

        start_count = self._count_remote_media()

        # Make two requests without responding to the outbound media requests.
        channel1, request1 = self._get_media_req(hs1, "example.com:443", "ABC123")
        channel2, request2 = self._get_media_req(hs2, "example.com:443", "ABC123")

        # Respond to the first outbound media request and check that the client
        # request is successful
        request1.setResponseCode(200)
        request1.responseHeaders.setRawHeaders(b"Content-Type", [b"text/plain"])
        request1.write(b"Hello!")
        request1.finish()

        self.pump(0.1)

        self.assertEqual(channel1.code, 200, channel1.result["body"])
        self.assertEqual(channel1.result["body"], b"Hello!")

        # Now respond to the second with the same content.
        request2.setResponseCode(200)
        request2.responseHeaders.setRawHeaders(b"Content-Type", [b"text/plain"])
        request2.write(b"Hello!")
        request2.finish()

        self.pump(0.1)

        self.assertEqual(channel2.code, 200, channel2.result["body"])
        self.assertEqual(channel2.result["body"], b"Hello!")

        # We expect only one new file to have been persisted.
        self.assertEqual(start_count + 1, self._count_remote_media())

    def test_download_image_race(self):
        """Test that fetching remote *images* from two different processes at
        the same time works.

        This checks that races generating thumbnails are handled correctly.
        """
        hs1 = self.make_worker_hs("synapse.app.generic_worker")
        hs2 = self.make_worker_hs("synapse.app.generic_worker")

        start_count = self._count_remote_thumbnails()

        channel1, request1 = self._get_media_req(hs1, "example.com:443", "PIC1")
        channel2, request2 = self._get_media_req(hs2, "example.com:443", "PIC1")

        png_data = unhexlify(
            b"89504e470d0a1a0a0000000d4948445200000001000000010806"
            b"0000001f15c4890000000a49444154789c63000100000500010d"
            b"0a2db40000000049454e44ae426082"
        )

        request1.setResponseCode(200)
        request1.responseHeaders.setRawHeaders(b"Content-Type", [b"image/png"])
        request1.write(png_data)
        request1.finish()

        self.pump(0.1)

        self.assertEqual(channel1.code, 200, channel1.result["body"])
        self.assertEqual(channel1.result["body"], png_data)

        request2.setResponseCode(200)
        request2.responseHeaders.setRawHeaders(b"Content-Type", [b"image/png"])
        request2.write(png_data)
        request2.finish()

        self.pump(0.1)

        self.assertEqual(channel2.code, 200, channel2.result["body"])
        self.assertEqual(channel2.result["body"], png_data)

        # We expect only three new thumbnails to have been persisted.
        self.assertEqual(start_count + 3, self._count_remote_thumbnails())

    def _count_remote_media(self) -> int:
        """Count the number of files in our remote media directory."""
        path = os.path.join(
            self.hs.get_media_repository().primary_base_path, "remote_content"
        )
        return sum(len(files) for _, _, files in os.walk(path))

    def _count_remote_thumbnails(self) -> int:
        """Count the number of files in our remote thumbnails directory."""
        path = os.path.join(
            self.hs.get_media_repository().primary_base_path, "remote_thumbnail"
        )
        return sum(len(files) for _, _, files in os.walk(path))


def get_connection_factory():
    # this needs to happen once, but not until we are ready to run the first test
    global test_server_connection_factory
    if test_server_connection_factory is None:
        test_server_connection_factory = TestServerTLSConnectionFactory(
            sanlist=[b"DNS:example.com"]
        )
    return test_server_connection_factory


def _build_test_server(connection_creator):
    """Construct a test server

    This builds an HTTP channel, wrapped with a TLSMemoryBIOProtocol

    Args:
        connection_creator (IOpenSSLServerConnectionCreator): thing to build
            SSL connections
        sanlist (list[bytes]): list of the SAN entries for the cert returned
            by the server

    Returns:
        TLSMemoryBIOProtocol
    """
    server_factory = Factory.forProtocol(HTTPChannel)
    # Request.finish expects the factory to have a 'log' method.
    server_factory.log = _log_request

    server_tls_factory = TLSMemoryBIOFactory(
        connection_creator, isClient=False, wrappedFactory=server_factory
    )

    return server_tls_factory.buildProtocol(None)


def _log_request(request):
    """Implements Factory.log, which is expected by Request.finish"""
    logger.info("Completed request %s", request)
