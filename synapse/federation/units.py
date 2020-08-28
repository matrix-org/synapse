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

import attr

from synapse.types import JsonDict
from synapse.util.jsonobject import JsonEncodedObject

logger = logging.getLogger(__name__)


@attr.s(slots=True)
class Edu(JsonEncodedObject):
    """ An Edu represents a piece of data sent from one homeserver to another.

    In comparison to Pdus, Edus are not persisted for a long time on disk, are
    not meaningful beyond a given pair of homeservers, and don't have an
    internal ID or previous references graph.
    """

    edu_type = attr.ib(type=str)
    content = attr.ib(type=dict)
    origin = attr.ib(type=str)
    destination = attr.ib(type=str)

    def get_dict(self) -> JsonDict:
        return {
            "edu_type": self.edu_type,
            "content": self.content,
        }

    def get_internal_dict(self) -> JsonDict:
        return {
            "edu_type": self.edu_type,
            "content": self.content,
            "origin": self.origin,
            "destination": self.destination,
        }

    def get_context(self):
        return getattr(self, "content", {}).get("org.matrix.opentracing_context", "{}")

    def strip_context(self):
        getattr(self, "content", {})["org.matrix.opentracing_context"] = "{}"


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

    internal_keys = ["transaction_id", "destination"]

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

        super().__init__(transaction_id=transaction_id, pdus=pdus, **kwargs)

    @staticmethod
    def create_new(pdus, **kwargs):
        """ Used to create a new transaction. Will auto fill out
        transaction_id and origin_server_ts keys.
        """
        if "origin_server_ts" not in kwargs:
            raise KeyError("Require 'origin_server_ts' to construct a Transaction")
        if "transaction_id" not in kwargs:
            raise KeyError("Require 'transaction_id' to construct a Transaction")

        kwargs["pdus"] = [p.get_pdu_json() for p in pdus]

        return Transaction(**kwargs)
