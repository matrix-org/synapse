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

import itertools
import logging

from synapse.util.jsonobject import JsonEncodedObject

logger = logging.getLogger(__name__)


BUCKETS = [0, 50, 100, 200, 350, 500, 750, 1000, 2000, 5000, 10000, 100000]


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
    pdu_json.pop("hashes", None)
    pdu_json.pop("signatures", None)

    pdu_json["auth_events"] = list(_strip_hashes(pdu_json["auth_events"]))
    pdu_json["prev_events"] = list(_strip_hashes(pdu_json["prev_events"]))

    destinations = pdu_json["unsigned"].pop("destinations", None)
    if destinations:
        new_destinations = {}
        for dest, cost in destinations.items():
            for first, second in pairwise(BUCKETS):
                if first <= cost <= second:
                    b = first if cost - first < second - cost else second
                    new_destinations.setdefault(b, []).append(dest)
                    break
            else:
                new_destinations.setdefault(b[-1], []).append(dest)

        pdu_json["unsigned"]["dtab"] = list(new_destinations.items())

    logger.info("Mangled PDU: %s", pdu_json)

    return pdu_json


def _strip_hashes(iterable):
    return (
        (e, {})
        for e, hashes in iterable
    )


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)
