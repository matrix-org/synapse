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

""" Defines the JSON structure of the protocol units used by the server to
server protocol.
"""

from synapse.util.jsonobject import JsonEncodedObject
from syutil.base64util import encode_base64

import logging
import json
import copy


logger = logging.getLogger(__name__)


class Pdu(JsonEncodedObject):
    """ A Pdu represents a piece of data sent from a server and is associated
    with a context.

    A Pdu can be classified as "state". For a given context, we can efficiently
    retrieve all state pdu's that haven't been clobbered. Clobbering is done
    via a unique constraint on the tuple (context, type, state_key). A pdu
    is a state pdu if `is_state` is True.

    Example pdu::

        {
            "event_id": "$78c:example.com",
            "origin_server_ts": 1404835423000,
            "origin": "bar",
            "prev_ids": [
                ["23b", "foo"],
                ["56a", "bar"],
            ],
            "content": { ... },
        }

    """

    valid_keys = [
        "event_id",
        "room_id",
        "origin",
        "origin_server_ts",
        "type",
        "destinations",
        "transaction_id",
        "prev_events",
        "depth",
        "content",
        "outlier",
        "hashes",
        "signatures",
        "is_state",  # Below this are keys valid only for State Pdus.
        "state_key",
        "prev_state",
        "required_power_level",
        "user_id",
    ]

    internal_keys = [
        "destinations",
        "transaction_id",
        "outlier",
    ]

    required_keys = [
        "event_id",
        "room_id",
        "origin",
        "origin_server_ts",
        "type",
        "content",
    ]

    # TODO: We need to make this properly load content rather than
    # just leaving it as a dict. (OR DO WE?!)

    def __init__(self, destinations=[], is_state=False, prev_events=[],
                 outlier=False, hashes={}, signatures={}, **kwargs):
        if is_state:
            for required_key in ["state_key"]:
                if required_key not in kwargs:
                    raise RuntimeError("Key %s is required" % required_key)

        super(Pdu, self).__init__(
            destinations=destinations,
            is_state=bool(is_state),
            prev_events=prev_events,
            outlier=outlier,
            hashes=hashes,
            signatures=signatures,
            **kwargs
        )

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
        "edu_type",
    ]

#    TODO: SYN-103: Remove "origin" and "destination" keys.
#    internal_keys = [
#        "origin",
#        "destination",
#    ]


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
        "transaction_id",
        "destination",
    ]

    internal_keys = [
        "transaction_id",
        "destination",
    ]

    required_keys = [
        "transaction_id",
        "origin",
        "destination",
        "origin_server_ts",
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
        if "origin_server_ts" not in kwargs:
            raise KeyError("Require 'origin_server_ts' to construct a Transaction")
        if "transaction_id" not in kwargs:
            raise KeyError(
                "Require 'transaction_id' to construct a Transaction"
            )

        for p in pdus:
            p.transaction_id = kwargs["transaction_id"]

        kwargs["pdus"] = [p.get_dict() for p in pdus]

        return Transaction(**kwargs)



