# Copyright 2014-2016 OpenMarket Ltd
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

import logging

import idna
from service_identity import VerificationError
from service_identity.pyopenssl import verify_hostname, verify_ip_address
from zope.interface import implementer

from OpenSSL import SSL, crypto
from twisted.internet._sslverify import _defaultCurveName
from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.internet.ssl import (
    CertificateOptions,
    ContextFactory,
    TLSVersion,
    platformTrust,
)
from twisted.python.failure import Failure

logger = logging.getLogger(__name__)


_TLS_VERSION_MAP = {
    "1": TLSVersion.TLSv1_0,
    "1.1": TLSVersion.TLSv1_1,
    "1.2": TLSVersion.TLSv1_2,
    "1.3": TLSVersion.TLSv1_3,
}


class ServerContextFactory(ContextFactory):
    """Factory for PyOpenSSL SSL contexts that are used to handle incoming
    connections."""

    def __init__(self, config):
        self._context = SSL.Context(SSL.SSLv23_METHOD)
        self.configure_context(self._context, config)

    @staticmethod
    def configure_context(context, config):
        try:
            _ecCurve = crypto.get_elliptic_curve(_defaultCurveName)
            context.set_tmp_ecdh(_ecCurve)
        except Exception:
            logger.exception("Failed to enable elliptic curve for TLS")

        context.set_options(
            SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1
        )
        context.use_certificate_chain_file(config.tls_certificate_file)
        context.use_privatekey(config.tls_private_key)

        # https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
        context.set_cipher_list(
            "ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES256:ECDH+AES128:!aNULL:!SHA1:!AESCCM"
        )

    def getContext(self):
        return self._context


class ClientTLSOptionsFactory(object):
    """Factory for Twisted SSLClientConnectionCreators that are used to make connections
    to remote servers for federation.

    Uses one of two OpenSSL context objects for all connections, depending on whether
    we should do SSL certificate verification.

    get_options decides whether we should do SSL certificate verification and
    constructs an SSLClientConnectionCreator factory accordingly.
    """

    def __init__(self, config):
        self._config = config

        # Check if we're using a custom list of a CA certificates
        trust_root = config.federation_ca_trust_root
        if trust_root is None:
            # Use CA root certs provided by OpenSSL
            trust_root = platformTrust()

        # "insecurelyLowerMinimumTo" is the argument that will go lower than
        # Twisted's default, which is why it is marked as "insecure" (since
        # Twisted's defaults are reasonably secure). But, since Twisted is
        # moving to TLS 1.2 by default, we want to respect the config option if
        # it is set to 1.0 (which the alternate option, raiseMinimumTo, will not
        # let us do).
        minTLS = _TLS_VERSION_MAP[config.federation_client_minimum_tls_version]

        self._verify_ssl = CertificateOptions(
            trustRoot=trust_root, insecurelyLowerMinimumTo=minTLS
        )
        self._verify_ssl_context = self._verify_ssl.getContext()
        self._verify_ssl_context.set_info_callback(self._context_info_cb)

        self._no_verify_ssl = CertificateOptions(insecurelyLowerMinimumTo=minTLS)
        self._no_verify_ssl_context = self._no_verify_ssl.getContext()
        self._no_verify_ssl_context.set_info_callback(self._context_info_cb)

    def get_options(self, host):
        # Check if certificate verification has been enabled
        should_verify = self._config.federation_verify_certificates

        # Check if we've disabled certificate verification for this host
        if should_verify:
            for regex in self._config.federation_certificate_verification_whitelist:
                if regex.match(host):
                    should_verify = False
                    break

        ssl_context = (
            self._verify_ssl_context if should_verify else self._no_verify_ssl_context
        )

        return SSLClientConnectionCreator(host, ssl_context, should_verify)

    @staticmethod
    def _context_info_cb(ssl_connection, where, ret):
        """The 'information callback' for our openssl context object."""
        # we assume that the app_data on the connection object has been set to
        # a TLSMemoryBIOProtocol object. (This is done by SSLClientConnectionCreator)
        tls_protocol = ssl_connection.get_app_data()
        try:
            # ... we further assume that SSLClientConnectionCreator has set the
            # '_synapse_tls_verifier' attribute to a ConnectionVerifier object.
            tls_protocol._synapse_tls_verifier.verify_context_info_cb(
                ssl_connection, where
            )
        except:  # noqa: E722, taken from the twisted implementation
            logger.exception("Error during info_callback")
            f = Failure()
            tls_protocol.failVerification(f)


@implementer(IOpenSSLClientConnectionCreator)
class SSLClientConnectionCreator(object):
    """Creates openssl connection objects for client connections.

    Replaces twisted.internet.ssl.ClientTLSOptions
    """

    def __init__(self, hostname, ctx, verify_certs):
        self._ctx = ctx
        self._verifier = ConnectionVerifier(hostname, verify_certs)

    def clientConnectionForTLS(self, tls_protocol):
        context = self._ctx
        connection = SSL.Connection(context, None)

        # as per twisted.internet.ssl.ClientTLSOptions, we set the application
        # data to our TLSMemoryBIOProtocol...
        connection.set_app_data(tls_protocol)

        # ... and we also gut-wrench a '_synapse_tls_verifier' attribute into the
        # tls_protocol so that the SSL context's info callback has something to
        # call to do the cert verification.
        setattr(tls_protocol, "_synapse_tls_verifier", self._verifier)
        return connection


class ConnectionVerifier(object):
    """Set the SNI, and do cert verification

    This is a thing which is attached to the TLSMemoryBIOProtocol, and is called by
    the ssl context's info callback.
    """

    # This code is based on twisted.internet.ssl.ClientTLSOptions.

    def __init__(self, hostname, verify_certs):
        self._verify_certs = verify_certs

        if isIPAddress(hostname) or isIPv6Address(hostname):
            self._hostnameBytes = hostname.encode("ascii")
            self._is_ip_address = True
        else:
            # twisted's ClientTLSOptions falls back to the stdlib impl here if
            # idna is not installed, but points out that lacks support for
            # IDNA2008 (http://bugs.python.org/issue17305).
            #
            # We can rely on having idna.
            self._hostnameBytes = idna.encode(hostname)
            self._is_ip_address = False

        self._hostnameASCII = self._hostnameBytes.decode("ascii")

    def verify_context_info_cb(self, ssl_connection, where):
        if where & SSL.SSL_CB_HANDSHAKE_START and not self._is_ip_address:
            ssl_connection.set_tlsext_host_name(self._hostnameBytes)

        if where & SSL.SSL_CB_HANDSHAKE_DONE and self._verify_certs:
            try:
                if self._is_ip_address:
                    verify_ip_address(ssl_connection, self._hostnameASCII)
                else:
                    verify_hostname(ssl_connection, self._hostnameASCII)
            except VerificationError:
                f = Failure()
                tls_protocol = ssl_connection.get_app_data()
                tls_protocol.failVerification(f)
