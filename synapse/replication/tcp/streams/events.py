# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2019 New Vector Ltd
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
from collections import namedtuple

from ._base import Stream

EventStreamRow = namedtuple("EventStreamRow", (
    "event_id",  # str
    "room_id",  # str
    "type",  # str
    "state_key",  # str, optional
    "redacts",  # str, optional
))


class EventsStream(Stream):
    """We received a new event, or an event went from being an outlier to not
    """
    NAME = "events"
    ROW_TYPE = EventStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        self.current_token = store.get_current_events_token
        self.update_function = store.get_all_new_forward_event_rows

        super(EventsStream, self).__init__(hs)
