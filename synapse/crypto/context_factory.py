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
from twisted.web.iweb import IPolicyForHTTPS

logger = logging.getLogger(__name__)


_TLS_VERSION_MAP = {
    "1": TLSVersion.TLSv1_0,
    "1.1": TLSVersion.TLSv1_1,
    "1.2": TLSVersion.TLSv1_2,
    "1.3": TLSVersion.TLSv1_3,
}


class ServerContextFactory(ContextFactory):
    """Factory for PyOpenSSL SSL contexts that are used to handle incoming
    connections.

    TODO: replace this with an implementation of IOpenSSLServerConnectionCreator,
    per https://github.com/matrix-org/synapse/issues/1691
    """

    def __init__(self, config):
        # TODO: once pyOpenSSL exposes TLS_METHOD and SSL_CTX_set_min_proto_version,
        # switch to those (see https://github.com/pyca/cryptography/issues/5379).
        #
        # note that, despite the confusing name, SSLv23_METHOD does *not* enforce SSLv2
        # or v3, but is a synonym for TLS_METHOD, which allows the client and server
        # to negotiate an appropriate version of TLS constrained by the version options
        # set with context.set_options.
        #
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


@implementer(IPolicyForHTTPS)
class FederationPolicyForHTTPS:
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

        _verify_ssl = CertificateOptions(
            trustRoot=trust_root, insecurelyLowerMinimumTo=minTLS
        )
        self._verify_ssl_context = _verify_ssl.getContext()
        self._verify_ssl_context.set_info_callback(_context_info_cb)

        _no_verify_ssl = CertificateOptions(insecurelyLowerMinimumTo=minTLS)
        self._no_verify_ssl_context = _no_verify_ssl.getContext()
        self._no_verify_ssl_context.set_info_callback(_context_info_cb)

        self._should_verify = self._config.federation_verify_certificates

        self._federation_certificate_verification_whitelist = (
            self._config.federation_certificate_verification_whitelist
        )

    def get_options(self, host: bytes):
        # IPolicyForHTTPS.get_options takes bytes, but we want to compare
        # against the str whitelist. The hostnames in the whitelist are already
        # IDNA-encoded like the hosts will be here.
        ascii_host = host.decode("ascii")

        # Check if certificate verification has been enabled
        should_verify = self._should_verify

        # Check if we've disabled certificate verification for this host
        if self._should_verify:
            for regex in self._federation_certificate_verification_whitelist:
                if regex.match(ascii_host):
                    should_verify = False
                    break

        ssl_context = (
            self._verify_ssl_context if should_verify else self._no_verify_ssl_context
        )

        return SSLClientConnectionCreator(host, ssl_context, should_verify)

    def creatorForNetloc(self, hostname, port):
        """Implements the IPolicyForHTTPS interface so that this can be passed
        directly to agents.
        """
        return self.get_options(hostname)


@implementer(IPolicyForHTTPS)
class RegularPolicyForHTTPS:
    """Factory for Twisted SSLClientConnectionCreators that are used to make connections
    to remote servers, for other than federation.

    Always uses the same OpenSSL context object, which uses the default OpenSSL CA
    trust root.
    """

    def __init__(self):
        trust_root = platformTrust()
        self._ssl_context = CertificateOptions(trustRoot=trust_root).getContext()
        self._ssl_context.set_info_callback(_context_info_cb)

    def creatorForNetloc(self, hostname, port):
        return SSLClientConnectionCreator(hostname, self._ssl_context, True)


def _context_info_cb(ssl_connection, where, ret):
    """The 'information callback' for our openssl context objects.

    Note: Once this is set as the info callback on a Context object, the Context should
    only be used with the SSLClientConnectionCreator.
    """
    # we assume that the app_data on the connection object has been set to
    # a TLSMemoryBIOProtocol object. (This is done by SSLClientConnectionCreator)
    tls_protocol = ssl_connection.get_app_data()
    try:
        # ... we further assume that SSLClientConnectionCreator has set the
        # '_synapse_tls_verifier' attribute to a ConnectionVerifier object.
        tls_protocol._synapse_tls_verifier.verify_context_info_cb(ssl_connection, where)
    except BaseException:  # taken from the twisted implementation
        logger.exception("Error during info_callback")
        f = Failure()
        tls_protocol.failVerification(f)


@implementer(IOpenSSLClientConnectionCreator)
class SSLClientConnectionCreator:
    """Creates openssl connection objects for client connections.

    Replaces twisted.internet.ssl.ClientTLSOptions
    """

    def __init__(self, hostname: bytes, ctx, verify_certs: bool):
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
        tls_protocol._synapse_tls_verifier = self._verifier
        return connection


class ConnectionVerifier:
    """Set the SNI, and do cert verification

    This is a thing which is attached to the TLSMemoryBIOProtocol, and is called by
    the ssl context's info callback.
    """

    # This code is based on twisted.internet.ssl.ClientTLSOptions.

    def __init__(self, hostname: bytes, verify_certs: bool):
        self._verify_certs = verify_certs

        _decoded = hostname.decode("ascii")
        if isIPAddress(_decoded) or isIPv6Address(_decoded):
            self._is_ip_address = True
        else:
            self._is_ip_address = False

        self._hostnameBytes = hostname
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
