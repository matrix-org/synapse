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


class SignatureStore(SQLBaseStore):
    """Persistence for PDU signatures and hashes"""

    def _get_pdu_hashes_txn(self, txn, pdu_id, origin):
        """Get all the hashes for a given PDU.
        Args:
            txn (cursor):
            pdu_id (str): Id for the PDU.
            origin (str): origin of the PDU.
        Returns:
            A dict of algorithm -> hash.
        """
        query = (
            "SELECT algorithm, hash"
            " FROM pdu_hashes"
            " WHERE pdu_id = ? and origin = ?"
        )
        txn.execute(query, (pdu_id, origin))
        return dict(txn.fetchall())

    def _store_pdu_hash_txn(self, txn, pdu_id, origin, algorithm, hash_bytes):
        """Store a hash for a PDU
        Args:
            txn (cursor):
            pdu_id (str): Id for the PDU.
            origin (str): origin of the PDU.
            algorithm (str): Hashing algorithm.
            hash_bytes (bytes): Hash function output bytes.
        """
        self._simple_insert_txn(self, txn, "pdu_hashes", {
            "pdu_id": pdu_id,
            "origin": origin,
            "algorithm": algorithm,
            "hash": buffer(hash_bytes),
        })

    def _get_pdu_origin_signatures_txn(self, txn, pdu_id, origin):
        """Get all the signatures for a given PDU.
        Args:
            txn (cursor):
            pdu_id (str): Id for the PDU.
            origin (str): origin of the PDU.
        Returns:
            A dict of key_id -> signature_bytes.
        """
        query = (
            "SELECT key_id, signature"
            " FROM pdu_origin_signatures"
            " WHERE WHERE pdu_id = ? and origin = ?"
        )
        txn.execute(query, (pdu_id, origin))
        return dict(txn.fetchall())

    def _store_pdu_origin_signature_txn(self, txn, pdu_id, origin, key_id,
                                        signature_bytes):
        """Store a signature from the origin server for a PDU.
        Args:
            txn (cursor):
            pdu_id (str): Id for the PDU.
            origin (str): origin of the PDU.
            key_id (str): Id for the signing key.
            signature (bytes): The signature.
        """
        self._simple_insert_txn(self, txn, "pdu_origin_signatures", {
            "pdu_id": pdu_id,
            "origin": origin,
            "key_id": key_id,
            "signature": buffer(signature_bytes),
        })

