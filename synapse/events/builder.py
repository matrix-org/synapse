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

from . import EventBase, FrozenEvent

from synapse.types import EventID

from synapse.util.stringutils import random_string

import copy


class EventBuilder(EventBase):
    def __init__(self, key_values={}):
        signatures = copy.deepcopy(key_values.pop("signatures", {}))
        unsigned = copy.deepcopy(key_values.pop("unsigned", {}))

        super(EventBuilder, self).__init__(
            key_values,
            signatures=signatures,
            unsigned=unsigned
        )

    def update_event_key(self, key, value):
        self._event_dict[key] = value

    def update_event_keys(self, other_dict):
        self._event_dict.update(other_dict)

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

        e_id = EventID.create(local_part, self.hostname)

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
