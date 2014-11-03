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

    def event_from_pdu(self, pdu):
        kwargs = {}

        kwargs["etype"] = pdu.type

        kwargs.update({
            k: v
            for k, v in pdu.get_full_dict().items()
            if k not in [
                "type",
            ]
        })

        return self.event_factory.create_event(**kwargs)

    def pdu_from_event(self, event):
        d = event.get_full_dict()

        if hasattr(event, "state_key"):
            d["is_state"] = True

        kwargs = copy.deepcopy(event.unrecognized_keys)
        kwargs.update({
            k: v for k, v in d.items()
        })

        if "origin_server_ts" not in kwargs:
            kwargs["origin_server_ts"] = int(self.clock.time_msec())

        pdu = Pdu(**kwargs)
        pdu = add_event_pdu_content_hash(pdu)
        return sign_event_pdu(pdu, self.server_name, self.signing_key)
