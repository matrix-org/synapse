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
from .units import Pdu

import copy


def decode_event_id(event_id, server_name):
    parts = event_id.split("@")
    if len(parts) < 2:
        return (event_id, server_name)
    else:
        return (parts[0], "".join(parts[1:]))


def encode_event_id(pdu_id, origin):
    return "%s@%s" % (pdu_id, origin)


class PduCodec(object):

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.event_factory = hs.get_event_factory()
        self.clock = hs.get_clock()

    def event_from_pdu(self, pdu):
        kwargs = {}

        kwargs["event_id"] = encode_event_id(pdu.pdu_id, pdu.origin)
        kwargs["room_id"] = pdu.context
        kwargs["etype"] = pdu.pdu_type
        kwargs["prev_events"] = [
            encode_event_id(p[0], p[1]) for p in pdu.prev_pdus
        ]

        if hasattr(pdu, "prev_state_id") and hasattr(pdu, "prev_state_origin"):
            kwargs["prev_state"] = encode_event_id(
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

        d["pdu_id"], d["origin"] = decode_event_id(
            event.event_id, self.server_name
        )
        d["context"] = event.room_id
        d["pdu_type"] = event.type

        if hasattr(event, "prev_events"):
            d["prev_pdus"] = [
                decode_event_id(e, self.server_name)
                for e in event.prev_events
            ]

        if hasattr(event, "prev_state"):
            d["prev_state_id"], d["prev_state_origin"] = (
                decode_event_id(event.prev_state, self.server_name)
            )

        if hasattr(event, "state_key"):
            d["is_state"] = True

        kwargs = copy.deepcopy(event.unrecognized_keys)
        kwargs.update({
            k: v for k, v in d.items()
            if k not in ["event_id", "room_id", "type", "prev_events"]
        })

        if "ts" not in kwargs:
            kwargs["ts"] = int(self.clock.time_msec())

        return Pdu(**kwargs)
