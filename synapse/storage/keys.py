# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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
from syutil.crypto.signing_key import decode_verify_key_bytes
import hashlib


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

    def store_server_certificate(self, server_name, from_server, time_now_ms,
                                 tls_certificate):
        """Stores the TLS X.509 certificate for the given server
        Args:
            server_name (str): The name of the server.
            from_server (str): Where the certificate was looked up
            time_now_ms (int): The time now in milliseconds
            tls_certificate (OpenSSL.crypto.X509): The X.509 certificate.
        """
        tls_certificate_bytes = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, tls_certificate
        )
        fingerprint = hashlib.sha256(tls_certificate_bytes).hexdigest()
        return self._simple_insert(
            table="server_tls_certificates",
            values={
                "server_name": server_name,
                "fingerprint": fingerprint,
                "from_server": from_server,
                "ts_added_ms": time_now_ms,
                "tls_certificate": buffer(tls_certificate_bytes),
            },
            or_ignore=True,
        )

    @defer.inlineCallbacks
    def get_server_verify_keys(self, server_name, key_ids):
        """Retrieve the NACL verification key for a given server for the given
        key_ids
        Args:
            server_name (str): The name of the server.
            key_ids (list of str): List of key_ids to try and look up.
        Returns:
            (list of VerifyKey): The verification keys.
        """
        sql = (
            "SELECT key_id, verify_key FROM server_signature_keys"
            " WHERE server_name = ?"
            " AND key_id in (" + ",".join("?" for key_id in key_ids) + ")"
        )

        rows = yield self._execute_and_decode(sql, server_name, *key_ids)

        keys = []
        for row in rows:
            key_id = row["key_id"]
            key_bytes = row["verify_key"]
            key = decode_verify_key_bytes(key_id, str(key_bytes))
            keys.append(key)
        defer.returnValue(keys)

    def store_server_verify_key(self, server_name, from_server, time_now_ms,
                                verify_key):
        """Stores a NACL verification key for the given server.
        Args:
            server_name (str): The name of the server.
            key_id (str): The version of the key for the server.
            from_server (str): Where the verification key was looked up
            ts_now_ms (int): The time now in milliseconds
            verification_key (VerifyKey): The NACL verify key.
        """
        return self._simple_insert(
            table="server_signature_keys",
            values={
                "server_name": server_name,
                "key_id": "%s:%s" % (verify_key.alg, verify_key.version),
                "from_server": from_server,
                "ts_added_ms": time_now_ms,
                "verify_key": buffer(verify_key.encode()),
            },
            or_ignore=True,
        )
