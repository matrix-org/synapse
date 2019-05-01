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
import heapq

import attr

from twisted.internet import defer

from ._base import Stream


"""Handling of the 'events' replication stream

This stream contains rows of various types. Each row therefore contains a 'type'
identifier before the real data. For example::

    RDATA events batch ["state", ["!room:id", "m.type", "", "$event:id"]]
    RDATA events 12345 ["ev", ["$event:id", "!room:id", "m.type", null, null]]

An "ev" row is sent for each new event. The fields in the data part are:

 * The new event id
 * The room id for the event
 * The type of the new event
 * The state key of the event, for state events
 * The event id of an event which is redacted by this event.

A "state" row is sent whenever the "current state" in a room changes. The fields in the
data part are:

 * The room id for the state change
 * The event type of the state which has changed
 * The state_key of the state which has changed
 * The event id of the new state

"""


@attr.s(slots=True, frozen=True)
class EventsStreamRow(object):
    """A parsed row from the events replication stream"""
    type = attr.ib()  # str: the TypeId of one of the *EventsStreamRows
    data = attr.ib()  # BaseEventsStreamRow


class BaseEventsStreamRow(object):
    """Base class for rows to be sent in the events stream.

    Specifies how to identify, serialize and deserialize the different types.
    """

    TypeId = None  # Unique string that ids the type. Must be overriden in sub classes.

    @classmethod
    def from_data(cls, data):
        """Parse the data from the replication stream into a row.

        By default we just call the constructor with the data list as arguments

        Args:
            data: The value of the data object from the replication stream
        """
        return cls(*data)


@attr.s(slots=True, frozen=True)
class EventsStreamEventRow(BaseEventsStreamRow):
    TypeId = "ev"

    event_id = attr.ib()   # str
    room_id = attr.ib()    # str
    type = attr.ib()       # str
    state_key = attr.ib()  # str, optional
    redacts = attr.ib()    # str, optional


@attr.s(slots=True, frozen=True)
class EventsStreamCurrentStateRow(BaseEventsStreamRow):
    TypeId = "state"

    room_id = attr.ib()    # str
    type = attr.ib()       # str
    state_key = attr.ib()  # str
    event_id = attr.ib()   # str, optional


TypeToRow = {
    Row.TypeId: Row
    for Row in (
        EventsStreamEventRow,
        EventsStreamCurrentStateRow,
    )
}


class EventsStream(Stream):
    """We received a new event, or an event went from being an outlier to not
    """
    NAME = "events"

    def __init__(self, hs):
        self._store = hs.get_datastore()
        self.current_token = self._store.get_current_events_token

        super(EventsStream, self).__init__(hs)

    @defer.inlineCallbacks
    def update_function(self, from_token, current_token, limit=None):
        event_rows = yield self._store.get_all_new_forward_event_rows(
            from_token, current_token, limit,
        )
        event_updates = (
            (row[0], EventsStreamEventRow.TypeId, row[1:])
            for row in event_rows
        )

        state_rows = yield self._store.get_all_updated_current_state_deltas(
            from_token, current_token, limit
        )
        state_updates = (
            (row[0], EventsStreamCurrentStateRow.TypeId, row[1:])
            for row in state_rows
        )

        all_updates = heapq.merge(event_updates, state_updates)

        defer.returnValue(all_updates)

    @classmethod
    def parse_row(cls, row):
        (typ, data) = row
        data = TypeToRow[typ].from_data(data)
        return EventsStreamRow(typ, data)
