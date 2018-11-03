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

from six import iteritems

from sortedcontainers import SortedDict

from synapse.metrics import LaterGauge
from synapse.storage.presence import UserPresenceState
from synapse.util.metrics import Measure

from .units import Edu

logger = logging.getLogger(__name__)


class FederationRemoteSendQueue(object):
    """A drop in replacement for TransactionQueue"""

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id

        self.presence_map = {}  # Pending presence map user_id -> UserPresenceState
        self.presence_changed = SortedDict()  # Stream position -> user_id

        self.keyed_edu = {}  # (destination, key) -> EDU
        self.keyed_edu_changed = SortedDict()  # stream position -> (destination, key)

        self.edus = SortedDict()  # stream position -> Edu

        self.device_messages = SortedDict()  # stream position -> destination

        self.pos = 1
        self.pos_time = SortedDict()

        # EVERYTHING IS SAD. In particular, python only makes new scopes when
        # we make a new function, so we need to make a new function so the inner
        # lambda binds to the queue rather than to the name of the queue which
        # changes. ARGH.
        def register(name, queue):
            LaterGauge("synapse_federation_send_queue_%s_size" % (queue_name,),
                       "", [], lambda: len(queue))

        for queue_name in [
            "presence_map", "presence_changed", "keyed_edu", "keyed_edu_changed",
            "edus", "device_messages", "pos_time",
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

            user_ids = set(
                user_id
                for uids in self.presence_changed.values()
                for user_id in uids
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

            to_del = [edu_key for edu_key in self.keyed_edu if edu_key not in live_keys]
            for edu_key in to_del:
                del self.keyed_edu[edu_key]

            # Delete things out of edu map
            keys = self.edus.keys()
            i = self.edus.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.edus[key]

            # Delete things out of device map
            keys = self.device_messages.keys()
            i = self.device_messages.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.device_messages[key]

    def notify_new_events(self, current_id):
        """As per TransactionQueue"""
        # We don't need to replicate this as it gets sent down a different
        # stream.
        pass

    def send_edu(self, destination, edu_type, content, key=None):
        """As per TransactionQueue"""
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

    def send_presence(self, states):
        """As per TransactionQueue

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

    def send_device_messages(self, destination):
        """As per TransactionQueue"""
        pos = self._next_pos()
        self.device_messages[pos] = destination
        self.notifier.on_new_replication_data()

    def get_current_token(self):
        return self.pos - 1

    def federation_ack(self, token):
        self._clear_queue_before_pos(token)

    def get_replication_rows(self, from_token, to_token, limit, federation_ack=None):
        """Get rows to be sent over federation between the two tokens

        Args:
            from_token (int)
            to_token(int)
            limit (int)
            federation_ack (int): Optional. The position where the worker is
                explicitly acknowledged it has handled. Allows us to drop
                data from before that point
        """
        # TODO: Handle limit.

        # To handle restarts where we wrap around
        if from_token > self.pos:
            from_token = -1

        # list of tuple(int, BaseFederationRow), where the first is the position
        # of the federation stream.
        rows = []

        # There should be only one reader, so lets delete everything its
        # acknowledged its seen.
        if federation_ack:
            self._clear_queue_before_pos(federation_ack)

        # Fetch changed presence
        i = self.presence_changed.bisect_right(from_token)
        j = self.presence_changed.bisect_right(to_token) + 1
        dest_user_ids = [
            (pos, user_id)
            for pos, user_id_list in self.presence_changed.items()[i:j]
            for user_id in user_id_list
        ]

        for (key, user_id) in dest_user_ids:
            rows.append((key, PresenceRow(
                state=self.presence_map[user_id],
            )))

        # Fetch changes keyed edus
        i = self.keyed_edu_changed.bisect_right(from_token)
        j = self.keyed_edu_changed.bisect_right(to_token) + 1
        # We purposefully clobber based on the key here, python dict comprehensions
        # always use the last value, so this will correctly point to the last
        # stream position.
        keyed_edus = {v: k for k, v in self.keyed_edu_changed.items()[i:j]}

        for ((destination, edu_key), pos) in iteritems(keyed_edus):
            rows.append((pos, KeyedEduRow(
                key=edu_key,
                edu=self.keyed_edu[(destination, edu_key)],
            )))

        # Fetch changed edus
        i = self.edus.bisect_right(from_token)
        j = self.edus.bisect_right(to_token) + 1
        edus = self.edus.items()[i:j]

        for (pos, edu) in edus:
            rows.append((pos, EduRow(edu)))

        # Fetch changed device messages
        i = self.device_messages.bisect_right(from_token)
        j = self.device_messages.bisect_right(to_token) + 1
        device_messages = {v: k for k, v in self.device_messages.items()[i:j]}

        for (destination, pos) in iteritems(device_messages):
            rows.append((pos, DeviceRow(
                destination=destination,
            )))

        # Sort rows based on pos
        rows.sort()

        return [(pos, row.TypeId, row.to_data()) for pos, row in rows]


class BaseFederationRow(object):
    """Base class for rows to be sent in the federation stream.

    Specifies how to identify, serialize and deserialize the different types.
    """

    TypeId = None  # Unique string that ids the type. Must be overriden in sub classes.

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


class PresenceRow(BaseFederationRow, namedtuple("PresenceRow", (
    "state",  # UserPresenceState
))):
    TypeId = "p"

    @staticmethod
    def from_data(data):
        return PresenceRow(
            state=UserPresenceState.from_dict(data)
        )

    def to_data(self):
        return self.state.as_dict()

    def add_to_buffer(self, buff):
        buff.presence.append(self.state)


class KeyedEduRow(BaseFederationRow, namedtuple("KeyedEduRow", (
    "key",  # tuple(str) - the edu key passed to send_edu
    "edu",  # Edu
))):
    """Streams EDUs that have an associated key that is ued to clobber. For example,
    typing EDUs clobber based on room_id.
    """

    TypeId = "k"

    @staticmethod
    def from_data(data):
        return KeyedEduRow(
            key=tuple(data["key"]),
            edu=Edu(**data["edu"]),
        )

    def to_data(self):
        return {
            "key": self.key,
            "edu": self.edu.get_internal_dict(),
        }

    def add_to_buffer(self, buff):
        buff.keyed_edus.setdefault(
            self.edu.destination, {}
        )[self.key] = self.edu


class EduRow(BaseFederationRow, namedtuple("EduRow", (
    "edu",  # Edu
))):
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


class DeviceRow(BaseFederationRow, namedtuple("DeviceRow", (
    "destination",  # str
))):
    """Streams the fact that either a) there is pending to device messages for
    users on the remote, or b) a local users device has changed and needs to
    be sent to the remote.
    """
    TypeId = "d"

    @staticmethod
    def from_data(data):
        return DeviceRow(destination=data["destination"])

    def to_data(self):
        return {"destination": self.destination}

    def add_to_buffer(self, buff):
        buff.device_destinations.add(self.destination)


TypeToRow = {
    Row.TypeId: Row
    for Row in (
        PresenceRow,
        KeyedEduRow,
        EduRow,
        DeviceRow,
    )
}


ParsedFederationStreamData = namedtuple("ParsedFederationStreamData", (
    "presence",  # list(UserPresenceState)
    "keyed_edus",  # dict of destination -> { key -> Edu }
    "edus",  # dict of destination -> [Edu]
    "device_destinations",  # set of destinations
))


def process_rows_for_federation(transaction_queue, rows):
    """Parse a list of rows from the federation stream and put them in the
    transaction queue ready for sending to the relevant homeservers.

    Args:
        transaction_queue (TransactionQueue)
        rows (list(synapse.replication.tcp.streams.FederationStreamRow))
    """

    # The federation stream contains a bunch of different types of
    # rows that need to be handled differently. We parse the rows, put
    # them into the appropriate collection and then send them off.

    buff = ParsedFederationStreamData(
        presence=[],
        keyed_edus={},
        edus={},
        device_destinations=set(),
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

    for destination, edu_map in iteritems(buff.keyed_edus):
        for key, edu in edu_map.items():
            transaction_queue.send_edu(
                edu.destination, edu.edu_type, edu.content, key=key,
            )

    for destination, edu_list in iteritems(buff.edus):
        for edu in edu_list:
            transaction_queue.send_edu(
                edu.destination, edu.edu_type, edu.content, key=None,
            )

    for destination in buff.device_destinations:
        transaction_queue.send_device_messages(destination)
