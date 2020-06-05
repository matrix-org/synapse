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

"""A federation sender that forwards things to be sent across replication to
a worker process.

It assumes there is a single worker process feeding off of it.

Each row in the replication stream consists of a type and some json, where the
types indicate whether they are presence, or edus, etc.

Ephemeral or non-event data are queued up in-memory. When the worker requests
updates since a particular point, all in-memory data since before that point is
dropped. We also expire things in the queue after 5 minutes, to ensure that a
dead worker doesn't cause the queues to grow limitlessly.

Events are replicated via a separate events stream.
"""

import logging
from collections import namedtuple
from typing import Dict, List, Tuple, Type

from six import iteritems

from sortedcontainers import SortedDict

from twisted.internet import defer

from synapse.metrics import LaterGauge
from synapse.storage.presence import UserPresenceState
from synapse.util.metrics import Measure

from .units import Edu

logger = logging.getLogger(__name__)


class FederationRemoteSendQueue(object):
    """A drop in replacement for FederationSender"""

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id

        # Pending presence map user_id -> UserPresenceState
        self.presence_map = {}  # type: Dict[str, UserPresenceState]

        # Stream position -> list[user_id]
        self.presence_changed = SortedDict()  # type: SortedDict[int, List[str]]

        # Stores the destinations we need to explicitly send presence to about a
        # given user.
        # Stream position -> (user_id, destinations)
        self.presence_destinations = (
            SortedDict()
        )  # type: SortedDict[int, Tuple[str, List[str]]]

        # (destination, key) -> EDU
        self.keyed_edu = {}  # type: Dict[Tuple[str, tuple], Edu]

        # stream position -> (destination, key)
        self.keyed_edu_changed = (
            SortedDict()
        )  # type: SortedDict[int, Tuple[str, tuple]]

        self.edus = SortedDict()  # type: SortedDict[int, Edu]

        # stream ID for the next entry into presence_changed/keyed_edu_changed/edus.
        self.pos = 1

        # map from stream ID to the time that stream entry was generated, so that we
        # can clear out entries after a while
        self.pos_time = SortedDict()  # type: SortedDict[int, int]

        # EVERYTHING IS SAD. In particular, python only makes new scopes when
        # we make a new function, so we need to make a new function so the inner
        # lambda binds to the queue rather than to the name of the queue which
        # changes. ARGH.
        def register(name, queue):
            LaterGauge(
                "synapse_federation_send_queue_%s_size" % (queue_name,),
                "",
                [],
                lambda: len(queue),
            )

        for queue_name in [
            "presence_map",
            "presence_changed",
            "keyed_edu",
            "keyed_edu_changed",
            "edus",
            "pos_time",
            "presence_destinations",
        ]:
            register(queue_name, getattr(self, queue_name))

        self.clock.looping_call(self._clear_queue, 30 * 1000)

    def _next_pos(self):
        pos = self.pos
        self.pos += 1
        self.pos_time[self.clock.time_msec()] = pos
        return pos

    def _clear_queue(self):
        """Clear the queues for anything older than N minutes"""

        FIVE_MINUTES_AGO = 5 * 60 * 1000
        now = self.clock.time_msec()

        keys = self.pos_time.keys()
        time = self.pos_time.bisect_left(now - FIVE_MINUTES_AGO)
        if not keys[:time]:
            return

        position_to_delete = max(keys[:time])
        for key in keys[:time]:
            del self.pos_time[key]

        self._clear_queue_before_pos(position_to_delete)

    def _clear_queue_before_pos(self, position_to_delete):
        """Clear all the queues from before a given position"""
        with Measure(self.clock, "send_queue._clear"):
            # Delete things out of presence maps
            keys = self.presence_changed.keys()
            i = self.presence_changed.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.presence_changed[key]

            user_ids = {
                user_id for uids in self.presence_changed.values() for user_id in uids
            }

            keys = self.presence_destinations.keys()
            i = self.presence_destinations.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.presence_destinations[key]

            user_ids.update(
                user_id for user_id, _ in self.presence_destinations.values()
            )

            to_del = [
                user_id for user_id in self.presence_map if user_id not in user_ids
            ]
            for user_id in to_del:
                del self.presence_map[user_id]

            # Delete things out of keyed edus
            keys = self.keyed_edu_changed.keys()
            i = self.keyed_edu_changed.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.keyed_edu_changed[key]

            live_keys = set()
            for edu_key in self.keyed_edu_changed.values():
                live_keys.add(edu_key)

            keys_to_del = [
                edu_key for edu_key in self.keyed_edu if edu_key not in live_keys
            ]
            for edu_key in keys_to_del:
                del self.keyed_edu[edu_key]

            # Delete things out of edu map
            keys = self.edus.keys()
            i = self.edus.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.edus[key]

    def notify_new_events(self, current_id):
        """As per FederationSender"""
        # We don't need to replicate this as it gets sent down a different
        # stream.
        pass

    def build_and_send_edu(self, destination, edu_type, content, key=None):
        """As per FederationSender"""
        if destination == self.server_name:
            logger.info("Not sending EDU to ourselves")
            return

        pos = self._next_pos()

        edu = Edu(
            origin=self.server_name,
            destination=destination,
            edu_type=edu_type,
            content=content,
        )

        if key:
            assert isinstance(key, tuple)
            self.keyed_edu[(destination, key)] = edu
            self.keyed_edu_changed[pos] = (destination, key)
        else:
            self.edus[pos] = edu

        self.notifier.on_new_replication_data()

    def send_read_receipt(self, receipt):
        """As per FederationSender

        Args:
            receipt (synapse.types.ReadReceipt):
        """
        # nothing to do here: the replication listener will handle it.
        return defer.succeed(None)

    def send_presence(self, states):
        """As per FederationSender

        Args:
            states (list(UserPresenceState))
        """
        pos = self._next_pos()

        # We only want to send presence for our own users, so lets always just
        # filter here just in case.
        local_states = list(filter(lambda s: self.is_mine_id(s.user_id), states))

        self.presence_map.update({state.user_id: state for state in local_states})
        self.presence_changed[pos] = [state.user_id for state in local_states]

        self.notifier.on_new_replication_data()

    def send_presence_to_destinations(self, states, destinations):
        """As per FederationSender

        Args:
            states (list[UserPresenceState])
            destinations (list[str])
        """
        for state in states:
            pos = self._next_pos()
            self.presence_map.update({state.user_id: state for state in states})
            self.presence_destinations[pos] = (state.user_id, destinations)

        self.notifier.on_new_replication_data()

    def send_device_messages(self, destination):
        """As per FederationSender"""
        # We don't need to replicate this as it gets sent down a different
        # stream.

    def get_current_token(self):
        return self.pos - 1

    def federation_ack(self, token):
        self._clear_queue_before_pos(token)

    async def get_replication_rows(
        self, instance_name: str, from_token: int, to_token: int, target_row_count: int
    ) -> Tuple[List[Tuple[int, Tuple]], int, bool]:
        """Get rows to be sent over federation between the two tokens

        Args:
            instance_name: the name of the current process
            from_token: the previous stream token: the starting point for fetching the
                updates
            to_token: the new stream token: the point to get updates up to
            target_row_count: a target for the number of rows to be returned.

        Returns: a triplet `(updates, new_last_token, limited)`, where:
           * `updates` is a list of `(token, row)` entries.
           * `new_last_token` is the new position in stream.
           * `limited` is whether there are more updates to fetch.
        """
        # TODO: Handle target_row_count.

        # To handle restarts where we wrap around
        if from_token > self.pos:
            from_token = -1

        # list of tuple(int, BaseFederationRow), where the first is the position
        # of the federation stream.
        rows = []  # type: List[Tuple[int, BaseFederationRow]]

        # Fetch changed presence
        i = self.presence_changed.bisect_right(from_token)
        j = self.presence_changed.bisect_right(to_token) + 1
        dest_user_ids = [
            (pos, user_id)
            for pos, user_id_list in self.presence_changed.items()[i:j]
            for user_id in user_id_list
        ]

        for (key, user_id) in dest_user_ids:
            rows.append((key, PresenceRow(state=self.presence_map[user_id])))

        # Fetch presence to send to destinations
        i = self.presence_destinations.bisect_right(from_token)
        j = self.presence_destinations.bisect_right(to_token) + 1

        for pos, (user_id, dests) in self.presence_destinations.items()[i:j]:
            rows.append(
                (
                    pos,
                    PresenceDestinationsRow(
                        state=self.presence_map[user_id], destinations=list(dests)
                    ),
                )
            )

        # Fetch changes keyed edus
        i = self.keyed_edu_changed.bisect_right(from_token)
        j = self.keyed_edu_changed.bisect_right(to_token) + 1
        # We purposefully clobber based on the key here, python dict comprehensions
        # always use the last value, so this will correctly point to the last
        # stream position.
        keyed_edus = {v: k for k, v in self.keyed_edu_changed.items()[i:j]}

        for ((destination, edu_key), pos) in iteritems(keyed_edus):
            rows.append(
                (
                    pos,
                    KeyedEduRow(
                        key=edu_key, edu=self.keyed_edu[(destination, edu_key)]
                    ),
                )
            )

        # Fetch changed edus
        i = self.edus.bisect_right(from_token)
        j = self.edus.bisect_right(to_token) + 1
        edus = self.edus.items()[i:j]

        for (pos, edu) in edus:
            rows.append((pos, EduRow(edu)))

        # Sort rows based on pos
        rows.sort()

        return (
            [(pos, (row.TypeId, row.to_data())) for pos, row in rows],
            to_token,
            False,
        )


class BaseFederationRow(object):
    """Base class for rows to be sent in the federation stream.

    Specifies how to identify, serialize and deserialize the different types.
    """

    TypeId = ""  # Unique string that ids the type. Must be overriden in sub classes.

    @staticmethod
    def from_data(data):
        """Parse the data from the federation stream into a row.

        Args:
            data: The value of ``data`` from FederationStreamRow.data, type
                depends on the type of stream
        """
        raise NotImplementedError()

    def to_data(self):
        """Serialize this row to be sent over the federation stream.

        Returns:
            The value to be sent in FederationStreamRow.data. The type depends
            on the type of stream.
        """
        raise NotImplementedError()

    def add_to_buffer(self, buff):
        """Add this row to the appropriate field in the buffer ready for this
        to be sent over federation.

        We use a buffer so that we can batch up events that have come in at
        the same time and send them all at once.

        Args:
            buff (BufferedToSend)
        """
        raise NotImplementedError()


class PresenceRow(
    BaseFederationRow, namedtuple("PresenceRow", ("state",))  # UserPresenceState
):
    TypeId = "p"

    @staticmethod
    def from_data(data):
        return PresenceRow(state=UserPresenceState.from_dict(data))

    def to_data(self):
        return self.state.as_dict()

    def add_to_buffer(self, buff):
        buff.presence.append(self.state)


class PresenceDestinationsRow(
    BaseFederationRow,
    namedtuple(
        "PresenceDestinationsRow",
        ("state", "destinations"),  # UserPresenceState  # list[str]
    ),
):
    TypeId = "pd"

    @staticmethod
    def from_data(data):
        return PresenceDestinationsRow(
            state=UserPresenceState.from_dict(data["state"]), destinations=data["dests"]
        )

    def to_data(self):
        return {"state": self.state.as_dict(), "dests": self.destinations}

    def add_to_buffer(self, buff):
        buff.presence_destinations.append((self.state, self.destinations))


class KeyedEduRow(
    BaseFederationRow,
    namedtuple(
        "KeyedEduRow",
        ("key", "edu"),  # tuple(str) - the edu key passed to send_edu  # Edu
    ),
):
    """Streams EDUs that have an associated key that is ued to clobber. For example,
    typing EDUs clobber based on room_id.
    """

    TypeId = "k"

    @staticmethod
    def from_data(data):
        return KeyedEduRow(key=tuple(data["key"]), edu=Edu(**data["edu"]))

    def to_data(self):
        return {"key": self.key, "edu": self.edu.get_internal_dict()}

    def add_to_buffer(self, buff):
        buff.keyed_edus.setdefault(self.edu.destination, {})[self.key] = self.edu


class EduRow(BaseFederationRow, namedtuple("EduRow", ("edu",))):  # Edu
    """Streams EDUs that don't have keys. See KeyedEduRow
    """

    TypeId = "e"

    @staticmethod
    def from_data(data):
        return EduRow(Edu(**data))

    def to_data(self):
        return self.edu.get_internal_dict()

    def add_to_buffer(self, buff):
        buff.edus.setdefault(self.edu.destination, []).append(self.edu)


_rowtypes = (
    PresenceRow,
    PresenceDestinationsRow,
    KeyedEduRow,
    EduRow,
)  # type: Tuple[Type[BaseFederationRow], ...]

TypeToRow = {Row.TypeId: Row for Row in _rowtypes}


ParsedFederationStreamData = namedtuple(
    "ParsedFederationStreamData",
    (
        "presence",  # list(UserPresenceState)
        "presence_destinations",  # list of tuples of UserPresenceState and destinations
        "keyed_edus",  # dict of destination -> { key -> Edu }
        "edus",  # dict of destination -> [Edu]
    ),
)


def process_rows_for_federation(transaction_queue, rows):
    """Parse a list of rows from the federation stream and put them in the
    transaction queue ready for sending to the relevant homeservers.

    Args:
        transaction_queue (FederationSender)
        rows (list(synapse.replication.tcp.streams.federation.FederationStream.FederationStreamRow))
    """

    # The federation stream contains a bunch of different types of
    # rows that need to be handled differently. We parse the rows, put
    # them into the appropriate collection and then send them off.

    buff = ParsedFederationStreamData(
        presence=[], presence_destinations=[], keyed_edus={}, edus={},
    )

    # Parse the rows in the stream and add to the buffer
    for row in rows:
        if row.type not in TypeToRow:
            logger.error("Unrecognized federation row type %r", row.type)
            continue

        RowType = TypeToRow[row.type]
        parsed_row = RowType.from_data(row.data)
        parsed_row.add_to_buffer(buff)

    if buff.presence:
        transaction_queue.send_presence(buff.presence)

    for state, destinations in buff.presence_destinations:
        transaction_queue.send_presence_to_destinations(
            states=[state], destinations=destinations
        )

    for destination, edu_map in iteritems(buff.keyed_edus):
        for key, edu in edu_map.items():
            transaction_queue.send_edu(edu, key)

    for destination, edu_list in iteritems(buff.edus):
        for edu in edu_list:
            transaction_queue.send_edu(edu, None)
