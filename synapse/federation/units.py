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

""" Defines the JSON structure of the protocol units used by the server to
server protocol.
"""

import logging

from synapse.types import get_localpart_from_id, get_domain_from_id
from synapse.util.jsonobject import JsonEncodedObject

logger = logging.getLogger(__name__)


class Edu(JsonEncodedObject):
    """ An Edu represents a piece of data sent from one homeserver to another.

    In comparison to Pdus, Edus are not persisted for a long time on disk, are
    not meaningful beyond a given pair of homeservers, and don't have an
    internal ID or previous references graph.
    """

    valid_keys = [
        "origin",
        "destination",
        "edu_type",
        "content",
    ]

    required_keys = [
        "edu_type",
    ]

    internal_keys = [
        "origin",
        "destination",
    ]


class Transaction(JsonEncodedObject):
    """ A transaction is a list of Pdus and Edus to be sent to a remote home
    server with some extra metadata.

    Example transaction::

        {
            "origin": "foo",
            "prev_ids": ["abc", "def"],
            "pdus": [
                ...
            ],
        }

    """

    valid_keys = [
        "transaction_id",
        "origin",
        "destination",
        "origin_server_ts",
        "previous_ids",
        "pdus",
        "edus",
    ]

    internal_keys = [
        "transaction_id",
        "origin",
        "destination",
        "origin_server_ts",
        "previous_ids",
    ]

    required_keys = [
        "pdus",
    ]

    def __init__(self, transaction_id=None, pdus=[], **kwargs):
        """ If we include a list of pdus then we decode then as PDU's
        automatically.
        """

        # If there's no EDUs then remove the arg
        if "edus" in kwargs and not kwargs["edus"]:
            del kwargs["edus"]

        super(Transaction, self).__init__(
            transaction_id=transaction_id,
            pdus=pdus,
            **kwargs
        )

    @staticmethod
    def create_new(pdus, **kwargs):
        """ Used to create a new transaction. Will auto fill out
        transaction_id and origin_server_ts keys.
        """
        kwargs["pdus"] = [
            _mangle_pdu(p.get_pdu_json())
            for p in pdus
        ]

        return Transaction(**kwargs)


def _mangle_pdu(pdu_json):
    pdu_json.pop("origin", None)
    pdu_json.pop("hashes", None)
    pdu_json.pop("signatures", None)
    pdu_json.get("unsigned", {}).pop("age_ts", None)
    pdu_json.get("unsigned", {}).pop("age", None)

    pdu_json["auth_events"] = list(_strip_hashes(pdu_json["auth_events"]))
    pdu_json["prev_events"] = list(_strip_hashes(pdu_json["prev_events"]))

    if get_domain_from_id(pdu_json["event_id"]) == get_domain_from_id(pdu_json["sender"]):
        pdu_json["event_id"] = get_localpart_from_id(pdu_json["event_id"])

    logger.info("Mangled PDU: %s", pdu_json)

    return pdu_json


def _strip_hashes(iterable):
    return (
        e for e, hashes in iterable
    )
