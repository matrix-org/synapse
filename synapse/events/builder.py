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

from . import EventBase, FrozenEvent, _event_dict_property

from synapse.types import EventID

from synapse.util.stringutils import random_string

import copy


class EventBuilder(EventBase):
    def __init__(self, key_values={}, internal_metadata_dict={}):
        signatures = copy.deepcopy(key_values.pop("signatures", {}))
        unsigned = copy.deepcopy(key_values.pop("unsigned", {}))

        self._event_dict = key_values

        super(EventBuilder, self).__init__(
            signatures=signatures,
            unsigned=unsigned,
            internal_metadata_dict=internal_metadata_dict,
        )

    event_id = _event_dict_property("event_id")
    state_key = _event_dict_property("state_key")
    type = _event_dict_property("type")

    auth_events = _event_dict_property("auth_events")
    depth = _event_dict_property("depth")
    content = _event_dict_property("content")
    hashes = _event_dict_property("hashes")
    origin = _event_dict_property("origin")
    origin_server_ts = _event_dict_property("origin_server_ts")
    prev_events = _event_dict_property("prev_events")
    prev_state = _event_dict_property("prev_state")
    redacts = _event_dict_property("redacts")
    room_id = _event_dict_property("room_id")
    sender = _event_dict_property("sender")
    user_id = _event_dict_property("sender")

    def get_dict(self):
        d = dict(self._event_dict)
        d.update({
            "signatures": self.signatures,
            "unsigned": dict(self.unsigned),
        })

        return d

    def get(self, key, default=None):
        return self._event_dict.get(key, default)

    def iteritems(self):
        return self._event_dict.iteritems()

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
