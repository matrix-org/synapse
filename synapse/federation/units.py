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
""" Defines the JSON structure of the protocol units used by the server to
server protocol.
"""

from synapse.util.jsonobject import JsonEncodedObject

import logging
import json
import copy


logger = logging.getLogger(__name__)


class Pdu(JsonEncodedObject):
    """ A Pdu represents a piece of data sent from a server and is associated
    with a context.

    A Pdu can be classified as "state". For a given context, we can efficiently
    retrieve all state pdu's that haven't been clobbered. Clobbering is done
    via a unique constraint on the tuple (context, pdu_type, state_key). A pdu
    is a state pdu if `is_state` is True.

    Example pdu::

        {
            "pdu_id": "78c",
            "ts": 1404835423000,
            "origin": "bar",
            "prev_ids": [
                ["23b", "foo"],
                ["56a", "bar"],
            ],
            "content": { ... },
        }

    """

    valid_keys = [
        "pdu_id",
        "context",
        "origin",
        "ts",
        "pdu_type",
        "destinations",
        "transaction_id",
        "prev_pdus",
        "depth",
        "content",
        "outlier",
        "is_state",  # Below this are keys valid only for State Pdus.
        "state_key",
        "power_level",
        "prev_state_id",
        "prev_state_origin",
    ]

    internal_keys = [
        "destinations",
        "transaction_id",
        "outlier",
    ]

    required_keys = [
        "pdu_id",
        "context",
        "origin",
        "ts",
        "pdu_type",
        "content",
    ]

    # TODO: We need to make this properly load content rather than
    # just leaving it as a dict. (OR DO WE?!)

    def __init__(self, destinations=[], is_state=False, prev_pdus=[],
                 outlier=False, **kwargs):
        if is_state:
            for required_key in ["state_key"]:
                if required_key not in kwargs:
                    raise RuntimeError("Key %s is required" % required_key)

        super(Pdu, self).__init__(
            destinations=destinations,
            is_state=is_state,
            prev_pdus=prev_pdus,
            outlier=outlier,
            **kwargs
        )

    @classmethod
    def from_pdu_tuple(cls, pdu_tuple):
        """ Converts a PduTuple to a Pdu

        Args:
            pdu_tuple (synapse.persistence.transactions.PduTuple): The tuple to
                convert

        Returns:
            Pdu
        """
        if pdu_tuple:
            d = copy.copy(pdu_tuple.pdu_entry._asdict())

            d["content"] = json.loads(d["content_json"])
            del d["content_json"]

            args = {f: d[f] for f in cls.valid_keys if f in d}
            if "unrecognized_keys" in d and d["unrecognized_keys"]:
                args.update(json.loads(d["unrecognized_keys"]))

            return Pdu(
                prev_pdus=pdu_tuple.prev_pdu_list,
                **args
            )
        else:
            return None

    def __str__(self):
        return "(%s, %s)" % (self.__class__.__name__, repr(self.__dict__))

    def __repr__(self):
        return "<%s, %s>" % (self.__class__.__name__, repr(self.__dict__))


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
        "origin",
        "destination",
        "edu_type",
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
        "ts",
        "previous_ids",
        "pdus",
        "edus",
    ]

    internal_keys = [
        "transaction_id",
        "destination",
    ]

    required_keys = [
        "transaction_id",
        "origin",
        "destination",
        "ts",
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
        transaction_id and ts keys.
        """
        if "ts" not in kwargs:
            raise KeyError("Require 'ts' to construct a Transaction")
        if "transaction_id" not in kwargs:
            raise KeyError(
                "Require 'transaction_id' to construct a Transaction"
            )

        for p in pdus:
            p.transaction_id = kwargs["transaction_id"]

        kwargs["pdus"] = [p.get_dict() for p in pdus]

        return Transaction(**kwargs)



