# -*- coding: utf-8 -*-
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

from ._base import SQLBaseStore
from synapse.util.caches.descriptors import cachedInlineCallbacks

from twisted.internet import defer

import OpenSSL
from signedjson.key import decode_verify_key_bytes
import hashlib

import logging

logger = logging.getLogger(__name__)


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
            desc="get_server_certificate",
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
        return self._simple_upsert(
            table="server_tls_certificates",
            keyvalues={
                "server_name": server_name,
                "fingerprint": fingerprint,
            },
            values={
                "from_server": from_server,
                "ts_added_ms": time_now_ms,
                "tls_certificate": buffer(tls_certificate_bytes),
            },
            desc="store_server_certificate",
        )

    @cachedInlineCallbacks()
    def _get_server_verify_key(self, server_name, key_id):
        verify_key_bytes = yield self._simple_select_one_onecol(
            table="server_signature_keys",
            keyvalues={
                "server_name": server_name,
                "key_id": key_id,
            },
            retcol="verify_key",
            desc="_get_server_verify_key",
            allow_none=True,
        )

        if verify_key_bytes:
            defer.returnValue(decode_verify_key_bytes(
                key_id, str(verify_key_bytes)
            ))

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
        keys = {}
        for key_id in key_ids:
            key = yield self._get_server_verify_key(server_name, key_id)
            if key:
                keys[key_id] = key
        defer.returnValue(keys)

    @defer.inlineCallbacks
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
        yield self._simple_upsert(
            table="server_signature_keys",
            keyvalues={
                "server_name": server_name,
                "key_id": "%s:%s" % (verify_key.alg, verify_key.version),
            },
            values={
                "from_server": from_server,
                "ts_added_ms": time_now_ms,
                "verify_key": buffer(verify_key.encode()),
            },
            desc="store_server_verify_key",
        )

    def store_server_keys_json(self, server_name, key_id, from_server,
                               ts_now_ms, ts_expires_ms, key_json_bytes):
        """Stores the JSON bytes for a set of keys from a server
        The JSON should be signed by the originating server, the intermediate
        server, and by this server. Updates the value for the
        (server_name, key_id, from_server) triplet if one already existed.
        Args:
            server_name (str): The name of the server.
            key_id (str): The identifer of the key this JSON is for.
            from_server (str): The server this JSON was fetched from.
            ts_now_ms (int): The time now in milliseconds.
            ts_valid_until_ms (int): The time when this json stops being valid.
            key_json (bytes): The encoded JSON.
        """
        return self._simple_upsert(
            table="server_keys_json",
            keyvalues={
                "server_name": server_name,
                "key_id": key_id,
                "from_server": from_server,
            },
            values={
                "server_name": server_name,
                "key_id": key_id,
                "from_server": from_server,
                "ts_added_ms": ts_now_ms,
                "ts_valid_until_ms": ts_expires_ms,
                "key_json": buffer(key_json_bytes),
            },
            desc="store_server_keys_json",
        )

    def get_server_keys_json(self, server_keys):
        """Retrive the key json for a list of server_keys and key ids.
        If no keys are found for a given server, key_id and source then
        that server, key_id, and source triplet entry will be an empty list.
        The JSON is returned as a byte array so that it can be efficiently
        used in an HTTP response.
        Args:
            server_keys (list): List of (server_name, key_id, source) triplets.
        Returns:
            Dict mapping (server_name, key_id, source) triplets to dicts with
            "ts_valid_until_ms" and "key_json" keys.
        """
        def _get_server_keys_json_txn(txn):
            results = {}
            for server_name, key_id, from_server in server_keys:
                keyvalues = {"server_name": server_name}
                if key_id is not None:
                    keyvalues["key_id"] = key_id
                if from_server is not None:
                    keyvalues["from_server"] = from_server
                rows = self._simple_select_list_txn(
                    txn,
                    "server_keys_json",
                    keyvalues=keyvalues,
                    retcols=(
                        "key_id",
                        "from_server",
                        "ts_added_ms",
                        "ts_valid_until_ms",
                        "key_json",
                    ),
                )
                results[(server_name, key_id, from_server)] = rows
            return results
        return self.runInteraction(
            "get_server_keys_json", _get_server_keys_json_txn
        )
