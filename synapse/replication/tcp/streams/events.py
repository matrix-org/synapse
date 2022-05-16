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
from typing import TYPE_CHECKING, Iterable, Optional, Tuple, Type, TypeVar, cast

import attr

from synapse.replication.tcp.streams._base import (
    Stream,
    StreamRow,
    StreamUpdateResult,
    Token,
)

if TYPE_CHECKING:
    from synapse.server import HomeServer

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


@attr.s(slots=True, frozen=True, auto_attribs=True)
class EventsStreamRow:
    """A parsed row from the events replication stream"""

    type: str  # the TypeId of one of the *EventsStreamRows
    data: "BaseEventsStreamRow"


T = TypeVar("T", bound="BaseEventsStreamRow")


class BaseEventsStreamRow:
    """Base class for rows to be sent in the events stream.

    Specifies how to identify, serialize and deserialize the different types.
    """

    # Unique string that ids the type. Must be overridden in sub classes.
    TypeId: str

    @classmethod
    def from_data(cls: Type[T], data: Iterable[Optional[str]]) -> T:
        """Parse the data from the replication stream into a row.

        By default we just call the constructor with the data list as arguments

        Args:
            data: The value of the data object from the replication stream
        """
        return cls(*data)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class EventsStreamEventRow(BaseEventsStreamRow):
    TypeId = "ev"

    event_id: str
    room_id: str
    type: str
    state_key: Optional[str]
    redacts: Optional[str]
    relates_to: Optional[str]
    membership: Optional[str]
    rejected: bool


@attr.s(slots=True, frozen=True, auto_attribs=True)
class EventsStreamCurrentStateRow(BaseEventsStreamRow):
    TypeId = "state"

    room_id: str
    type: str
    state_key: str
    event_id: Optional[str]


_EventRows: Tuple[Type[BaseEventsStreamRow], ...] = (
    EventsStreamEventRow,
    EventsStreamCurrentStateRow,
)

TypeToRow = {Row.TypeId: Row for Row in _EventRows}


class EventsStream(Stream):
    """We received a new event, or an event went from being an outlier to not"""

    NAME = "events"

    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastores().main
        super().__init__(
            hs.get_instance_name(),
            self._store._stream_id_gen.get_current_token_for_writer,
            self._update_function,
        )

    async def _update_function(
        self,
        instance_name: str,
        from_token: Token,
        current_token: Token,
        target_row_count: int,
    ) -> StreamUpdateResult:

        # the events stream merges together three separate sources:
        #  * new events
        #  * current_state changes
        #  * events which were previously outliers, but have now been de-outliered.
        #
        # The merge operation is complicated by the fact that we only have a single
        # "stream token" which is supposed to indicate how far we have got through
        # all three streams. It's therefore no good to return rows 1-1000 from the
        # "new events" table if the state_deltas are limited to rows 1-100 by the
        # target_row_count.
        #
        # In other words: we must pick a new upper limit, and must return *all* rows
        # up to that point for each of the three sources.
        #
        # Start by trying to split the target_row_count up. We expect to have a
        # negligible number of ex-outliers, and a rough approximation based on recent
        # traffic on sw1v.org shows that there are approximately the same number of
        # event rows between a given pair of stream ids as there are state
        # updates, so let's split our target_row_count among those two types. The target
        # is only an approximation - it doesn't matter if we end up going a bit over it.

        target_row_count //= 2

        # now we fetch up to that many rows from the events table

        event_rows = await self._store.get_all_new_forward_event_rows(
            instance_name, from_token, current_token, target_row_count
        )

        # we rely on get_all_new_forward_event_rows strictly honouring the limit, so
        # that we know it is safe to just take upper_limit = event_rows[-1][0].
        assert (
            len(event_rows) <= target_row_count
        ), "get_all_new_forward_event_rows did not honour row limit"

        # if we hit the limit on event_updates, there's no point in going beyond the
        # last stream_id in the batch for the other sources.

        if len(event_rows) == target_row_count:
            limited = True
            upper_limit: int = event_rows[-1][0]
        else:
            limited = False
            upper_limit = current_token

        # next up is the state delta table.
        (
            state_rows,
            upper_limit,
            state_rows_limited,
        ) = await self._store.get_all_updated_current_state_deltas(
            instance_name, from_token, upper_limit, target_row_count
        )

        limited = limited or state_rows_limited

        # finally, fetch the ex-outliers rows. We assume there are few enough of these
        # not to bother with the limit.

        ex_outliers_rows = await self._store.get_ex_outlier_stream_rows(
            instance_name, from_token, upper_limit
        )

        # we now need to turn the raw database rows returned into tuples suitable
        # for the replication protocol (basically, we add an identifier to
        # distinguish the row type). At the same time, we can limit the event_rows
        # to the max stream_id from state_rows.

        event_updates: Iterable[Tuple[int, Tuple]] = (
            (stream_id, (EventsStreamEventRow.TypeId, rest))
            for (stream_id, *rest) in event_rows
            if stream_id <= upper_limit
        )

        state_updates: Iterable[Tuple[int, Tuple]] = (
            (stream_id, (EventsStreamCurrentStateRow.TypeId, rest))
            for (stream_id, *rest) in state_rows
        )

        ex_outliers_updates: Iterable[Tuple[int, Tuple]] = (
            (stream_id, (EventsStreamEventRow.TypeId, rest))
            for (stream_id, *rest) in ex_outliers_rows
        )

        # we need to return a sorted list, so merge them together.
        updates = list(heapq.merge(event_updates, state_updates, ex_outliers_updates))
        return updates, upper_limit, limited

    @classmethod
    def parse_row(cls, row: StreamRow) -> "EventsStreamRow":
        (typ, data) = cast(Tuple[str, Iterable[Optional[str]]], row)
        event_stream_row_data = TypeToRow[typ].from_data(data)
        return EventsStreamRow(typ, event_stream_row_data)
