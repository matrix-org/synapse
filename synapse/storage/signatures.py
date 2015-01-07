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

from twisted.internet import defer

from _base import SQLBaseStore

from syutil.base64util import encode_base64


class SignatureStore(SQLBaseStore):
    """Persistence for event signatures and hashes"""

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
        self._simple_insert_txn(
            txn,
            "event_content_hashes",
            {
                "event_id": event_id,
                "algorithm": algorithm,
                "hash": buffer(hash_bytes),
            },
            or_ignore=True,
        )

    def get_event_reference_hashes(self, event_ids):
        def f(txn):
            return [
                self._get_event_reference_hashes_txn(txn, ev)
                for ev in event_ids
            ]

        return self.runInteraction(
            "get_event_reference_hashes",
            f
        )

    @defer.inlineCallbacks
    def add_event_hashes(self, event_ids):
        hashes = yield self.get_event_reference_hashes(
            event_ids
        )
        hashes = [
            {
                k: encode_base64(v) for k, v in h.items()
                if k == "sha256"
            }
            for h in hashes
        ]

        defer.returnValue(zip(event_ids, hashes))

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
        self._simple_insert_txn(
            txn,
            "event_reference_hashes",
            {
                "event_id": event_id,
                "algorithm": algorithm,
                "hash": buffer(hash_bytes),
            },
            or_ignore=True,
        )

    def _get_event_signatures_txn(self, txn, event_id):
        """Get all the signatures for a given PDU.
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
        Returns:
            A dict of sig name -> dict(key_id -> signature_bytes)
        """
        query = (
            "SELECT signature_name, key_id, signature"
            " FROM event_signatures"
            " WHERE event_id = ? "
        )
        txn.execute(query, (event_id, ))
        rows = txn.fetchall()

        res = {}

        for name, key, sig in rows:
            res.setdefault(name, {})[key] = sig

        return res

    def _store_event_signature_txn(self, txn, event_id, signature_name, key_id,
                                   signature_bytes):
        """Store a signature from the origin server for a PDU.
        Args:
            txn (cursor):
            event_id (str): Id for the Event.
            origin (str): origin of the Event.
            key_id (str): Id for the signing key.
            signature (bytes): The signature.
        """
        self._simple_insert_txn(
            txn,
            "event_signatures",
            {
                "event_id": event_id,
                "signature_name": signature_name,
                "key_id": key_id,
                "signature": buffer(signature_bytes),
            },
            or_ignore=True,
        )

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
        self._simple_insert_txn(
            txn,
            "event_edge_hashes",
            {
                "event_id": event_id,
                "prev_event_id": prev_event_id,
                "algorithm": algorithm,
                "hash": buffer(hash_bytes),
            },
            or_ignore=True,
        )
