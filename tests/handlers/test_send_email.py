# Copyright 2021 The Matrix.org Foundation C.I.C.
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


from typing import Callable, List, Tuple, Type, Union
from unittest.mock import patch

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet._sslverify import ClientTLSOptions
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.defer import ensureDeferred
from twisted.internet.interfaces import IProtocolFactory
from twisted.internet.ssl import ContextFactory
from twisted.mail import interfaces, smtp

from tests.server import FakeTransport
from tests.unittest import HomeserverTestCase, override_config


def TestingESMTPTLSClientFactory(
    contextFactory: ContextFactory,
    _connectWrapped: bool,
    wrappedProtocol: IProtocolFactory,
) -> IProtocolFactory:
    """We use this to pass through in testing without using TLS, but
    saving the context information to check that it would have happened.

    Note that this is what the MemoryReactor does on connectSSL.
    It only saves the contextFactory, but starts the connection with the
    underlying Factory.
    See: L{twisted.internet.testing.MemoryReactor.connectSSL}"""

    wrappedProtocol._testingContextFactory = contextFactory  # type: ignore[attr-defined]
    return wrappedProtocol


@implementer(interfaces.IMessageDelivery)
class _DummyMessageDelivery:
    def __init__(self) -> None:
        # (recipient, message) tuples
        self.messages: List[Tuple[smtp.Address, bytes]] = []

    def receivedHeader(
        self,
        helo: Tuple[bytes, bytes],
        origin: smtp.Address,
        recipients: List[smtp.User],
    ) -> None:
        return None

    def validateFrom(
        self, helo: Tuple[bytes, bytes], origin: smtp.Address
    ) -> smtp.Address:
        return origin

    def record_message(self, recipient: smtp.Address, message: bytes) -> None:
        self.messages.append((recipient, message))

    def validateTo(self, user: smtp.User) -> Callable[[], interfaces.IMessageSMTP]:
        return lambda: _DummyMessage(self, user)


@implementer(interfaces.IMessageSMTP)
class _DummyMessage:
    """IMessageSMTP implementation which saves the message delivered to it
    to the _DummyMessageDelivery object.
    """

    def __init__(self, delivery: _DummyMessageDelivery, user: smtp.User):
        self._delivery = delivery
        self._user = user
        self._buffer: List[bytes] = []

    def lineReceived(self, line: bytes) -> None:
        self._buffer.append(line)

    def eomReceived(self) -> "defer.Deferred[bytes]":
        message = b"\n".join(self._buffer) + b"\n"
        self._delivery.record_message(self._user.dest, message)
        return defer.succeed(b"saved")

    def connectionLost(self) -> None:
        pass


class SendEmailHandlerTestCaseIPv4(HomeserverTestCase):
    ip_class: Union[Type[IPv4Address], Type[IPv6Address]] = IPv4Address

    def setUp(self) -> None:
        super().setUp()
        self.reactor.lookups["localhost"] = "127.0.0.1"

    def test_send_email(self) -> None:
        """Happy-path test that we can send email to a non-TLS server."""
        h = self.hs.get_send_email_handler()
        d = ensureDeferred(
            h.send_email(
                "foo@bar.com", "test subject", "Tests", "HTML content", "Text content"
            )
        )
        # there should be an attempt to connect to localhost:25
        self.assertEqual(len(self.reactor.tcpClients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = self.reactor.tcpClients[
            0
        ]
        self.assertEqual(host, self.reactor.lookups["localhost"])
        self.assertEqual(port, 25)

        # wire it up to an SMTP server
        message_delivery = _DummyMessageDelivery()
        server_protocol = smtp.ESMTP()
        server_protocol.delivery = message_delivery
        # make sure that the server uses the test reactor to set timeouts
        server_protocol.callLater = self.reactor.callLater  # type: ignore[assignment]

        client_protocol = client_factory.buildProtocol(None)
        client_protocol.makeConnection(FakeTransport(server_protocol, self.reactor))
        server_protocol.makeConnection(
            FakeTransport(
                client_protocol,
                self.reactor,
                peer_address=self.ip_class(
                    "TCP", self.reactor.lookups["localhost"], 1234
                ),
            )
        )

        # the message should now get delivered
        self.get_success(d, by=0.1)

        # check it arrived
        self.assertEqual(len(message_delivery.messages), 1)
        user, msg = message_delivery.messages.pop()
        self.assertEqual(str(user), "foo@bar.com")
        self.assertIn(b"Subject: test subject", msg)

    @patch(
        "synapse.handlers.send_email.TLSMemoryBIOFactory",
        TestingESMTPTLSClientFactory,
    )
    @override_config(
        {
            "email": {
                "notif_from": "noreply@test",
                "force_tls": True,
            },
        }
    )
    def test_send_email_force_tls(self) -> None:
        """Happy-path test that we can send email to an Implicit TLS server."""
        h = self.hs.get_send_email_handler()
        d = ensureDeferred(
            h.send_email(
                "foo@bar.com", "test subject", "Tests", "HTML content", "Text content"
            )
        )
        # there should be an attempt to connect to localhost:465
        self.assertEqual(len(self.reactor.tcpClients), 1)
        (
            host,
            port,
            client_factory,
            _timeout,
            _bindAddress,
        ) = self.reactor.tcpClients[0]
        self.assertEqual(host, self.reactor.lookups["localhost"])
        self.assertEqual(port, 465)
        # We need to make sure that TLS is happenning
        self.assertIsInstance(
            client_factory._wrappedFactory._testingContextFactory,
            ClientTLSOptions,
        )
        # And since we use endpoints, they go through reactor.connectTCP
        # which works differently to connectSSL on the testing reactor

        # wire it up to an SMTP server
        message_delivery = _DummyMessageDelivery()
        server_protocol = smtp.ESMTP()
        server_protocol.delivery = message_delivery
        # make sure that the server uses the test reactor to set timeouts
        server_protocol.callLater = self.reactor.callLater  # type: ignore[assignment]

        client_protocol = client_factory.buildProtocol(None)
        client_protocol.makeConnection(FakeTransport(server_protocol, self.reactor))
        server_protocol.makeConnection(
            FakeTransport(
                client_protocol,
                self.reactor,
                peer_address=self.ip_class(
                    "TCP", self.reactor.lookups["localhost"], 1234
                ),
            )
        )

        # the message should now get delivered
        self.get_success(d, by=0.1)

        # check it arrived
        self.assertEqual(len(message_delivery.messages), 1)
        user, msg = message_delivery.messages.pop()
        self.assertEqual(str(user), "foo@bar.com")
        self.assertIn(b"Subject: test subject", msg)


class SendEmailHandlerTestCaseIPv6(SendEmailHandlerTestCaseIPv4):
    ip_class = IPv6Address

    def setUp(self) -> None:
        super().setUp()
        self.reactor.lookups["localhost"] = "::1"
