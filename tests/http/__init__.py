# Copyright 2019 New Vector Ltd
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
import os.path
import subprocess
from typing import List

from incremental import Version
from zope.interface import implementer

import twisted
from OpenSSL import SSL
from OpenSSL.SSL import Connection
from twisted.internet.address import IPv4Address
from twisted.internet.interfaces import (
    IOpenSSLServerConnectionCreator,
    IProtocolFactory,
    IReactorTime,
)
from twisted.internet.ssl import Certificate, trustRootFromCertificates
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.web.client import BrowserLikePolicyForHTTPS  # noqa: F401
from twisted.web.iweb import IPolicyForHTTPS  # noqa: F401


def get_test_https_policy() -> BrowserLikePolicyForHTTPS:
    """Get a test IPolicyForHTTPS which trusts the test CA cert

    Returns:
        IPolicyForHTTPS
    """
    ca_file = get_test_ca_cert_file()
    with open(ca_file) as stream:
        content = stream.read()
    cert = Certificate.loadPEM(content)
    trust_root = trustRootFromCertificates([cert])
    return BrowserLikePolicyForHTTPS(trustRoot=trust_root)


def get_test_ca_cert_file() -> str:
    """Get the path to the test CA cert

    The keypair is generated with:

        openssl genrsa -out ca.key 2048
        openssl req -new -x509 -key ca.key -days 3650 -out ca.crt \
            -subj '/CN=synapse test CA'
    """
    return os.path.join(os.path.dirname(__file__), "ca.crt")


def get_test_key_file() -> str:
    """get the path to the test key

    The key file is made with:

        openssl genrsa -out server.key 2048
    """
    return os.path.join(os.path.dirname(__file__), "server.key")


cert_file_count = 0

CONFIG_TEMPLATE = b"""\
[default]
basicConstraints = CA:FALSE
keyUsage=nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = %(sanentries)s
"""


def create_test_cert_file(sanlist: List[bytes]) -> str:
    """build an x509 certificate file

    Args:
        sanlist: a list of subjectAltName values for the cert

    Returns:
        The path to the file
    """
    global cert_file_count
    csr_filename = "server.csr"
    cnf_filename = "server.%i.cnf" % (cert_file_count,)
    cert_filename = "server.%i.crt" % (cert_file_count,)
    cert_file_count += 1

    # first build a CSR
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            get_test_key_file(),
            "-subj",
            "/",
            "-out",
            csr_filename,
        ]
    )

    # now a config file describing the right SAN entries
    sanentries = b",".join(sanlist)
    with open(cnf_filename, "wb") as f:
        f.write(CONFIG_TEMPLATE % {b"sanentries": sanentries})

    # finally the cert
    ca_key_filename = os.path.join(os.path.dirname(__file__), "ca.key")
    ca_cert_filename = get_test_ca_cert_file()
    subprocess.check_call(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            csr_filename,
            "-CA",
            ca_cert_filename,
            "-CAkey",
            ca_key_filename,
            "-set_serial",
            "1",
            "-extfile",
            cnf_filename,
            "-out",
            cert_filename,
        ]
    )

    return cert_filename


@implementer(IOpenSSLServerConnectionCreator)
class TestServerTLSConnectionFactory:
    """An SSL connection creator which returns connections which present a certificate
    signed by our test CA."""

    def __init__(self, sanlist: List[bytes]):
        """
        Args:
            sanlist: a list of subjectAltName values for the cert
        """
        self._cert_file = create_test_cert_file(sanlist)

    def serverConnectionForTLS(self, tlsProtocol: TLSMemoryBIOProtocol) -> Connection:
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.use_certificate_file(self._cert_file)
        ctx.use_privatekey_file(get_test_key_file())
        return Connection(ctx, None)


def wrap_server_factory_for_tls(
    factory: IProtocolFactory, clock: IReactorTime, sanlist: List[bytes]
) -> TLSMemoryBIOFactory:
    """Wrap an existing Protocol Factory with a test TLSMemoryBIOFactory

    The resultant factory will create a TLS server which presents a certificate
    signed by our test CA, valid for the domains in `sanlist`

    Args:
        factory: protocol factory to wrap
        sanlist: list of domains the cert should be valid for

    Returns:
        interfaces.IProtocolFactory
    """
    connection_creator = TestServerTLSConnectionFactory(sanlist=sanlist)
    # Twisted > 23.8.0 has a different API that accepts a clock.
    if twisted.version <= Version("Twisted", 23, 8, 0):
        return TLSMemoryBIOFactory(
            connection_creator, isClient=False, wrappedFactory=factory
        )
    else:
        return TLSMemoryBIOFactory(
            connection_creator, isClient=False, wrappedFactory=factory, clock=clock
        )


# A dummy address, useful for tests that use FakeTransport and don't care about where
# packets are going to/coming from.
dummy_address = IPv4Address("TCP", "127.0.0.1", 80)
