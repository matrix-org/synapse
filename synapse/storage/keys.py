# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from _base import SQLBaseStore

from twisted.internet import defer

import OpenSSL
import nacl.signing

class KeyStore(SQLBaseStore):
    """Persistence for signature verification keys and tls X.509 certificates
    """

    @defer.inlineCallbacks
    def get_server_certificate(self, server_name):
        """Retrieve the TLS X.509 certificate for the given server
        Args:
            server_name (bytes): The name of the server.
        Returns:
            (OpenSSL.crypto.X509): The tls certificate.
        """
        tls_certificate_bytes, = yield self._simple_select_one(
            table="server_tls_certificates",
            keyvalues={"server_name": server_name},
            retcols=("tls_certificate",),
        )
        tls_certificate = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, tls_certificate_bytes,
        )
        defer.returnValue(tls_certificate)

    def store_server_certificate(self, server_name, key_server, ts_now_ms,
                                 tls_certificate):
        """Stores the TLS X.509 certificate for the given server
        Args:
            server_name (bytes): The name of the server.
            key_server (bytes): Where the certificate was looked up
            ts_now_ms (int): The time now in milliseconds
            tls_certificate (OpenSSL.crypto.X509): The X.509 certificate.
        """
        tls_certificate_bytes = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, tls_certificate
        )
        return self._simple_insert(
            table="server_tls_certificates",
            keyvalues={
                "server_name": server_name,
                "key_server": key_server,
                "ts_added_ms": ts_now_ms,
                "tls_certificate": tls_certificate_bytes,
            },
        )

    @defer.inlineCallbacks
    def get_server_verification_key(self, server_name):
        """Retrieve the NACL verification key for a given server
        Args:
            server_name (bytes): The name of the server.
        Returns:
            (nacl.signing.VerifyKey): The verification key.
        """
        verification_key_bytes, = yield self._simple_select_one(
            table="server_signature_keys",
            key_values={"server_name": server_name},
            retcols=("tls_certificate",),
        )
        verification_key = nacl.signing.VerifyKey(verification_key_bytes)
        defer.returnValue(verification_key)

    def store_server_verification_key(self, server_name, key_version,
                                      key_server, ts_now_ms, verification_key):
        """Stores a NACL verification key for the given server.
        Args:
            server_name (bytes): The name of the server.
            key_version (bytes): The version of the key for the server.
            key_server (bytes): Where the verification key was looked up
            ts_now_ms (int): The time now in milliseconds
            verification_key (nacl.signing.VerifyKey): The NACL verify key.
        """
        verification_key_bytes = verification_key.encode()
        return self._simple_insert(
            table="server_signature_keys",
            key_values={
                "server_name": server_name,
                "key_version": key_version,
                "key_server": key_server,
                "ts_added_ms": ts_now_ms,
                "verification_key": verification_key_bytes,
            },
        )
