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

import copy

from synapse.types import EventID
from synapse.util.stringutils import random_string

from . import EventBase, FrozenEvent, _event_dict_property


class EventBuilder(EventBase):
    def __init__(self, key_values={}, internal_metadata_dict={}):
        signatures = copy.deepcopy(key_values.pop("signatures", {}))
        unsigned = copy.deepcopy(key_values.pop("unsigned", {}))

        super(EventBuilder, self).__init__(
            key_values,
            signatures=signatures,
            unsigned=unsigned,
            internal_metadata_dict=internal_metadata_dict,
        )

    event_id = _event_dict_property("event_id")
    state_key = _event_dict_property("state_key")
    type = _event_dict_property("type")

    def build(self):
        return FrozenEvent.from_event(self)


class EventBuilderFactory(object):
    def __init__(self, clock, hostname):
        self.clock = clock
        self.hostname = hostname

        self.event_id_count = 0

    def create_event_id(self):
        i = str(self.event_id_count)
        self.event_id_count += 1

        local_part = str(int(self.clock.time())) + i + random_string(5)

        e_id = EventID(local_part, self.hostname)

        return e_id.to_string()

    def new(self, key_values={}):
        key_values["event_id"] = self.create_event_id()

        time_now = int(self.clock.time_msec())

        key_values.setdefault("origin", self.hostname)
        key_values.setdefault("origin_server_ts", time_now)

        key_values.setdefault("unsigned", {})
        age = key_values["unsigned"].pop("age", 0)
        key_values["unsigned"].setdefault("age_ts", time_now - age)

        key_values["signatures"] = {}

        return EventBuilder(key_values=key_values,)
