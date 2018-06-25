# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet import ssl
from OpenSSL import SSL, crypto
from twisted.internet._sslverify import _defaultCurveName, ClientTLSOptions, \
    OpenSSLCertificateOptions, optionsForClientTLS

import logging

logger = logging.getLogger(__name__)


class ServerContextFactory(ssl.ContextFactory):
    """Factory for PyOpenSSL SSL contexts that are used to handle incoming
    connections and to make connections to remote servers."""

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
        context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        context.use_certificate_chain_file(config.tls_certificate_file)

        if not config.no_tls:
            context.use_privatekey(config.tls_private_key)

        context.load_tmp_dh(config.tls_dh_params_path)
        context.set_cipher_list("!ADH:HIGH+kEDH:!AECDH:HIGH+kEECDH")

    def getContext(self):
        return self._context


class ClientTLSOptionsNoCertVerification(ClientTLSOptions):
    """Redefinition of ClientTLSOptions to completely ignore certificate
    validation. Should be kept in sync with the original class in Twisted.
    This version of ClientTLSOptions is only intended for development use."""

    def __init__(self, *args, **kwargs):
        super(ClientTLSOptionsNoCertVerification, self).__init__(*args, **kwargs)

        def do_nothing(*_args, **_kwargs):
            pass

        self._ctx.set_info_callback(do_nothing)


class ClientTLSOptionsFactory(object):
    """Factory for Twisted ClientTLSOptions that are used to make connections
    to remote servers for federation."""

    def __init__(self, config):
        self._ignore_certificate_validation = config.tls_ignore_certificate_validation

    def get_options(self, host):
        if self._ignore_certificate_validation:
            return ClientTLSOptionsNoCertVerification(
                unicode(host),
                OpenSSLCertificateOptions(verify=False).getContext()
            )
        else:
            return optionsForClientTLS(unicode(host))
