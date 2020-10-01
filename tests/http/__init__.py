# -*- coding: utf-8 -*-
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

from zope.interface import implementer

from OpenSSL import SSL
from OpenSSL.SSL import Connection
from twisted.internet.interfaces import IOpenSSLServerConnectionCreator
from twisted.internet.ssl import Certificate, trustRootFromCertificates
from twisted.web.client import BrowserLikePolicyForHTTPS  # noqa: F401
from twisted.web.iweb import IPolicyForHTTPS  # noqa: F401


def get_test_https_policy():
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


def get_test_ca_cert_file():
    """Get the path to the test CA cert

    The keypair is generated with:

        openssl genrsa -out ca.key 2048
        openssl req -new -x509 -key ca.key -days 3650 -out ca.crt \
            -subj '/CN=synapse test CA'
    """
    return os.path.join(os.path.dirname(__file__), "ca.crt")


def get_test_key_file():
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


def create_test_cert_file(sanlist):
    """build an x509 certificate file

    Args:
        sanlist: list[bytes]: a list of subjectAltName values for the cert

    Returns:
        str: the path to the file
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

    def __init__(self, sanlist):
        """
        Args:
            sanlist: list[bytes]: a list of subjectAltName values for the cert
        """
        self._cert_file = create_test_cert_file(sanlist)

    def serverConnectionForTLS(self, tlsProtocol):
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.use_certificate_file(self._cert_file)
        ctx.use_privatekey_file(get_test_key_file())
        return Connection(ctx, None)
