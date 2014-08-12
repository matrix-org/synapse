# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from twisted.internet import reactor, ssl
from twisted.web import server
from twisted.web.resource import Resource
from twisted.python.log import PythonLoggingObserver

from synapse.crypto.resource.key import LocalKey
from synapse.crypto.config import load_config

from syutil.base64util import decode_base64

from OpenSSL import crypto, SSL

import logging
import nacl.signing
import sys


class KeyServerSSLContextFactory(ssl.ContextFactory):
    """Factory for PyOpenSSL SSL contexts that are used to handle incoming
    connections and to make connections to remote servers."""

    def __init__(self, key_server):
        self._context = SSL.Context(SSL.SSLv23_METHOD)
        self.configure_context(self._context, key_server)

    @staticmethod
    def configure_context(context, key_server):
        context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        context.use_certificate(key_server.tls_certificate)
        context.use_privatekey(key_server.tls_private_key)
        context.load_tmp_dh(key_server.tls_dh_params_path)
        context.set_cipher_list("!ADH:HIGH+kEDH:!AECDH:HIGH+kEECDH")

    def getContext(self):
        return self._context


class KeyServer(object):
    """An HTTPS server serving LocalKey and RemoteKey resources."""

    def __init__(self, server_name, tls_certificate_path, tls_private_key_path,
                 tls_dh_params_path, signing_key_path, bind_host, bind_port):
        self.server_name = server_name
        self.tls_certificate = self.read_tls_certificate(tls_certificate_path)
        self.tls_private_key = self.read_tls_private_key(tls_private_key_path)
        self.tls_dh_params_path = tls_dh_params_path
        self.signing_key = self.read_signing_key(signing_key_path)
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.ssl_context_factory = KeyServerSSLContextFactory(self)

    @staticmethod
    def read_tls_certificate(cert_path):
        with open(cert_path) as cert_file:
            cert_pem = cert_file.read()
            return crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    @staticmethod
    def read_tls_private_key(private_key_path):
        with open(private_key_path) as private_key_file:
            private_key_pem = private_key_file.read()
            return crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)

    @staticmethod
    def read_signing_key(signing_key_path):
        with open(signing_key_path) as signing_key_file:
            signing_key_b64 = signing_key_file.read()
            signing_key_bytes = decode_base64(signing_key_b64)
            return nacl.signing.SigningKey(signing_key_bytes)

    def run(self):
        root = Resource()
        root.putChild("key", LocalKey(self))
        site = server.Site(root)
        reactor.listenSSL(
            self.bind_port,
            site,
            self.ssl_context_factory,
            interface=self.bind_host
        )

        logging.basicConfig(level=logging.DEBUG)
        observer = PythonLoggingObserver()
        observer.start()

        reactor.run()


def main():
    key_server = KeyServer(**load_config(__doc__, sys.argv[1:]))
    key_server.run()


if __name__ == "__main__":
    main()
