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


class SignatureStore(SQLBaseStore):
    """Persistence for PDU signatures and hashes"""

    def _get_pdu_content_hashes_txn(self, txn, pdu_id, origin):
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
            " FROM pdu_content_hashes"
            " WHERE pdu_id = ? and origin = ?"
        )
        txn.execute(query, (pdu_id, origin))
        return dict(txn.fetchall())

    def _store_pdu_content_hash_txn(self, txn, pdu_id, origin, algorithm,
                                    hash_bytes):
        """Store a hash for a PDU
        Args:
            txn (cursor):
            pdu_id (str): Id for the PDU.
            origin (str): origin of the PDU.
            algorithm (str): Hashing algorithm.
            hash_bytes (bytes): Hash function output bytes.
        """
        self._simple_insert_txn(txn, "pdu_content_hashes", {
            "pdu_id": pdu_id,
            "origin": origin,
            "algorithm": algorithm,
            "hash": buffer(hash_bytes),
        })

    def _get_pdu_reference_hashes_txn(self, txn, pdu_id, origin):
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
            " FROM pdu_reference_hashes"
            " WHERE pdu_id = ? and origin = ?"
        )
        txn.execute(query, (pdu_id, origin))
        return dict(txn.fetchall())

    def _store_pdu_reference_hash_txn(self, txn, pdu_id, origin, algorithm,
                                      hash_bytes):
        """Store a hash for a PDU
        Args:
            txn (cursor):
            pdu_id (str): Id for the PDU.
            origin (str): origin of the PDU.
            algorithm (str): Hashing algorithm.
            hash_bytes (bytes): Hash function output bytes.
        """
        self._simple_insert_txn(txn, "pdu_reference_hashes", {
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
            " WHERE pdu_id = ? and origin = ?"
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
        self._simple_insert_txn(txn, "pdu_origin_signatures", {
            "pdu_id": pdu_id,
            "origin": origin,
            "key_id": key_id,
            "signature": buffer(signature_bytes),
        })

    def _get_prev_pdu_hashes_txn(self, txn, pdu_id, origin):
        """Get all the hashes for previous PDUs of a PDU
        Args:
            txn (cursor):
            pdu_id (str): Id of the PDU.
            origin (str): Origin of the PDU.
        Returns:
            dict of (pdu_id, origin) -> dict of algorithm -> hash_bytes.
        """
        query = (
            "SELECT prev_pdu_id, prev_origin, algorithm, hash"
            " FROM pdu_edge_hashes"
            " WHERE pdu_id = ? and origin = ?"
        )
        txn.execute(query, (pdu_id, origin))
        results = {}
        for prev_pdu_id, prev_origin, algorithm, hash_bytes in txn.fetchall():
            hashes = results.setdefault((prev_pdu_id, prev_origin), {})
            hashes[algorithm] = hash_bytes
        return results

    def _store_prev_pdu_hash_txn(self, txn, pdu_id, origin, prev_pdu_id,
                             prev_origin, algorithm, hash_bytes):
        self._simple_insert_txn(txn, "pdu_edge_hashes", {
            "pdu_id": pdu_id,
            "origin": origin,
            "prev_pdu_id": prev_pdu_id,
            "prev_origin": prev_origin,
            "algorithm": algorithm,
            "hash": buffer(hash_bytes),
        })

    ## Events ##

    def _get_event_content_hashes_txn(self, txn, event_id):
        """Get all the hashes for a given Event.
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
        Returns:
            A dict of algorithm -> hash.
        """
        query = (
            "SELECT algorithm, hash"
            " FROM event_content_hashes"
            " WHERE event_id = ?"
        )
        txn.execute(query, (event_id, ))
        return dict(txn.fetchall())

    def _store_event_content_hash_txn(self, txn, event_id, algorithm,
                                    hash_bytes):
        """Store a hash for a Event
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
            algorithm (str): Hashing algorithm.
            hash_bytes (bytes): Hash function output bytes.
        """
        self._simple_insert_txn(txn, "event_content_hashes", {
            "event_id": event_id,
            "algorithm": algorithm,
            "hash": buffer(hash_bytes),
        })

    def _get_event_reference_hashes_txn(self, txn, event_id):
        """Get all the hashes for a given PDU.
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
        Returns:
            A dict of algorithm -> hash.
        """
        query = (
            "SELECT algorithm, hash"
            " FROM event_reference_hashes"
            " WHERE event_id = ?"
        )
        txn.execute(query, (event_id, ))
        return dict(txn.fetchall())

    def _store_event_reference_hash_txn(self, txn, event_id, algorithm,
                                      hash_bytes):
        """Store a hash for a PDU
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
            algorithm (str): Hashing algorithm.
            hash_bytes (bytes): Hash function output bytes.
        """
        self._simple_insert_txn(txn, "event_reference_hashes", {
            "event_id": event_id,
            "algorithm": algorithm,
            "hash": buffer(hash_bytes),
        })


    def _get_event_origin_signatures_txn(self, txn, event_id):
        """Get all the signatures for a given PDU.
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
        Returns:
            A dict of key_id -> signature_bytes.
        """
        query = (
            "SELECT key_id, signature"
            " FROM event_origin_signatures"
            " WHERE event_id = ? "
        )
        txn.execute(query, (event_id, ))
        return dict(txn.fetchall())

    def _store_event_origin_signature_txn(self, txn, event_id, origin, key_id,
                                          signature_bytes):
        """Store a signature from the origin server for a PDU.
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
            origin (str): origin of the Event.
            key_id (str): Id for the signing key.
            signature (bytes): The signature.
        """
        self._simple_insert_txn(txn, "event_origin_signatures", {
            "event_id": event_id,
            "origin": origin,
            "key_id": key_id,
            "signature": buffer(signature_bytes),
        })

    def _get_prev_event_hashes_txn(self, txn, event_id):
        """Get all the hashes for previous PDUs of a PDU
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
        Returns:
            dict of (pdu_id, origin) -> dict of algorithm -> hash_bytes.
        """
        query = (
            "SELECT prev_event_id, algorithm, hash"
            " FROM event_edge_hashes"
            " WHERE event_id = ?"
        )
        txn.execute(query, (event_id, ))
        results = {}
        for prev_event_id, algorithm, hash_bytes in txn.fetchall():
            hashes = results.setdefault(prev_event_id, {})
            hashes[algorithm] = hash_bytes
        return results

    def _store_prev_event_hash_txn(self, txn, event_id, prev_event_id,
                                 algorithm, hash_bytes):
        self._simple_insert_txn(txn, "event_edge_hashes", {
            "event_id": event_id,
            "prev_event_id": prev_event_id,
            "algorithm": algorithm,
            "hash": buffer(hash_bytes),
        })