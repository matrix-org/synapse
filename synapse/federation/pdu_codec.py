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

from .units import Pdu
from synapse.crypto.event_signing import (
    add_event_pdu_content_hash, sign_event_pdu
)
from synapse.types import EventID

import copy


class PduCodec(object):

    def __init__(self, hs):
        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname
        self.event_factory = hs.get_event_factory()
        self.clock = hs.get_clock()
        self.hs = hs

    def encode_event_id(self, local, domain):
        return local

    def decode_event_id(self, event_id):
        e_id = self.hs.parse_eventid(event_id)
        return event_id, e_id.domain

    def event_from_pdu(self, pdu):
        kwargs = {}

        kwargs["event_id"] = self.encode_event_id(pdu.pdu_id, pdu.origin)
        kwargs["room_id"] = pdu.context
        kwargs["etype"] = pdu.pdu_type
        kwargs["prev_events"] = [
            (self.encode_event_id(i, o), s)
            for i, o, s in pdu.prev_pdus
        ]

        if hasattr(pdu, "prev_state_id") and hasattr(pdu, "prev_state_origin"):
            kwargs["prev_state"] = self.encode_event_id(
                pdu.prev_state_id, pdu.prev_state_origin
            )

        kwargs.update({
            k: v
            for k, v in pdu.get_full_dict().items()
            if k not in [
                "pdu_id",
                "context",
                "pdu_type",
                "prev_pdus",
                "prev_state_id",
                "prev_state_origin",
            ]
        })

        return self.event_factory.create_event(**kwargs)

    def pdu_from_event(self, event):
        d = event.get_full_dict()

        d["pdu_id"], d["origin"] = self.decode_event_id(
            event.event_id
        )
        d["context"] = event.room_id
        d["pdu_type"] = event.type

        if hasattr(event, "prev_events"):
            def f(e, s):
                i, o = self.decode_event_id(e)
                return i, o, s
            d["prev_pdus"] = [
                f(e, s)
                for e, s in event.prev_events
            ]

        if hasattr(event, "prev_state"):
            d["prev_state_id"], d["prev_state_origin"] = (
                self.decode_event_id(event.prev_state)
            )

        if hasattr(event, "state_key"):
            d["is_state"] = True

        kwargs = copy.deepcopy(event.unrecognized_keys)
        kwargs.update({
            k: v for k, v in d.items()
            if k not in ["event_id", "room_id", "type", "prev_events"]
        })

        if "origin_server_ts" not in kwargs:
            kwargs["origin_server_ts"] = int(self.clock.time_msec())

        pdu = Pdu(**kwargs)
        pdu = add_event_pdu_content_hash(pdu)
        return sign_event_pdu(pdu, self.server_name, self.signing_key)
