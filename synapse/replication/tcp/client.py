# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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
"""A replication client for use by synapse workers.
"""
import logging
from typing import TYPE_CHECKING, Dict, List, Tuple

from twisted.internet.defer import Deferred
from twisted.internet.protocol import ReconnectingClientFactory

from synapse.api.constants import EventTypes
from synapse.logging.context import PreserveLoggingContext, make_deferred_yieldable
from synapse.replication.tcp.protocol import ClientReplicationStreamProtocol
from synapse.replication.tcp.streams import TypingStream
from synapse.replication.tcp.streams.events import (
    EventsStream,
    EventsStreamEventRow,
    EventsStreamRow,
)
from synapse.types import PersistedEventPosition, UserID
from synapse.util.async_helpers import timeout_deferred
from synapse.util.metrics import Measure

if TYPE_CHECKING:
    from synapse.replication.tcp.handler import ReplicationCommandHandler
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# How long we allow callers to wait for replication updates before timing out.
_WAIT_FOR_REPLICATION_TIMEOUT_SECONDS = 30


class DirectTcpReplicationClientFactory(ReconnectingClientFactory):
    """Factory for building connections to the master. Will reconnect if the
    connection is lost.

    Accepts a handler that is passed to `ClientReplicationStreamProtocol`.
    """

    initialDelay = 0.1
    maxDelay = 1  # Try at least once every N seconds

    def __init__(
        self,
        hs: "HomeServer",
        client_name: str,
        command_handler: "ReplicationCommandHandler",
    ):
        self.client_name = client_name
        self.command_handler = command_handler
        self.server_name = hs.config.server_name
        self.hs = hs
        self._clock = hs.get_clock()  # As self.clock is defined in super class

        hs.get_reactor().addSystemEventTrigger("before", "shutdown", self.stopTrying)

    def startedConnecting(self, connector):
        logger.info("Connecting to replication: %r", connector.getDestination())

    def buildProtocol(self, addr):
        logger.info("Connected to replication: %r", addr)
        return ClientReplicationStreamProtocol(
            self.hs,
            self.client_name,
            self.server_name,
            self._clock,
            self.command_handler,
        )

    def clientConnectionLost(self, connector, reason):
        logger.error("Lost replication conn: %r", reason)
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        logger.error("Failed to connect to replication: %r", reason)
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)


class ReplicationDataHandler:
    """Handles incoming stream updates from replication.

    This instance notifies the slave data store about updates. Can be subclassed
    to handle updates in additional ways.
    """

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self._reactor = hs.get_reactor()
        self._clock = hs.get_clock()
        self._streams = hs.get_replication_streams()
        self._instance_name = hs.get_instance_name()
        self._typing_handler = hs.get_typing_handler()

        # Map from stream to list of deferreds waiting for the stream to
        # arrive at a particular position. The lists are sorted by stream position.
        self._streams_to_waiters = (
            {}
        )  # type: Dict[str, List[Tuple[int, Deferred[None]]]]

    async def on_rdata(
        self, stream_name: str, instance_name: str, token: int, rows: list
    ):
        """Called to handle a batch of replication data with a given stream token.

        By default this just pokes the slave store. Can be overridden in subclasses to
        handle more.

        Args:
            stream_name: name of the replication stream for this batch of rows
            instance_name: the instance that wrote the rows.
            token: stream token for this batch of rows
            rows: a list of Stream.ROW_TYPE objects as returned by Stream.parse_row.
        """
        self.store.process_replication_rows(stream_name, instance_name, token, rows)

        if stream_name == TypingStream.NAME:
            self._typing_handler.process_replication_rows(token, rows)
            self.notifier.on_new_event(
                "typing_key", token, rooms=[row.room_id for row in rows]
            )

        if stream_name == EventsStream.NAME:
            # We shouldn't get multiple rows per token for events stream, so
            # we don't need to optimise this for multiple rows.
            for row in rows:
                if row.type != EventsStreamEventRow.TypeId:
                    continue
                assert isinstance(row, EventsStreamRow)

                event = await self.store.get_event(
                    row.data.event_id, allow_rejected=True
                )
                if event.rejected_reason:
                    continue

                extra_users = ()  # type: Tuple[UserID, ...]
                if event.type == EventTypes.Member:
                    extra_users = (UserID.from_string(event.state_key),)

                max_token = self.store.get_room_max_token()
                event_pos = PersistedEventPosition(instance_name, token)
                self.notifier.on_new_room_event(
                    event, event_pos, max_token, extra_users
                )

        # Notify any waiting deferreds. The list is ordered by position so we
        # just iterate through the list until we reach a position that is
        # greater than the received row position.
        waiting_list = self._streams_to_waiters.get(stream_name, [])

        # Index of first item with a position after the current token, i.e we
        # have called all deferreds before this index. If not overwritten by
        # loop below means either a) no items in list so no-op or b) all items
        # in list were called and so the list should be cleared. Setting it to
        # `len(list)` works for both cases.
        index_of_first_deferred_not_called = len(waiting_list)

        for idx, (position, deferred) in enumerate(waiting_list):
            if position <= token:
                try:
                    with PreserveLoggingContext():
                        deferred.callback(None)
                except Exception:
                    # The deferred has been cancelled or timed out.
                    pass
            else:
                # The list is sorted by position so we don't need to continue
                # checking any further entries in the list.
                index_of_first_deferred_not_called = idx
                break

        # Drop all entries in the waiting list that were called in the above
        # loop. (This maintains the order so no need to resort)
        waiting_list[:] = waiting_list[index_of_first_deferred_not_called:]

    async def on_position(self, stream_name: str, instance_name: str, token: int):
        self.store.process_replication_rows(stream_name, instance_name, token, [])

    def on_remote_server_up(self, server: str):
        """Called when get a new REMOTE_SERVER_UP command."""

    async def wait_for_stream_position(
        self, instance_name: str, stream_name: str, position: int
    ):
        """Wait until this instance has received updates up to and including
        the given stream position.
        """

        if instance_name == self._instance_name:
            # We don't get told about updates written by this process, and
            # anyway in that case we don't need to wait.
            return

        current_position = self._streams[stream_name].current_token(self._instance_name)
        if position <= current_position:
            # We're already past the position
            return

        # Create a new deferred that times out after N seconds, as we don't want
        # to wedge here forever.
        deferred = Deferred()
        deferred = timeout_deferred(
            deferred, _WAIT_FOR_REPLICATION_TIMEOUT_SECONDS, self._reactor
        )

        waiting_list = self._streams_to_waiters.setdefault(stream_name, [])

        waiting_list.append((position, deferred))
        waiting_list.sort(key=lambda t: t[0])

        # We measure here to get in flight counts and average waiting time.
        with Measure(self._clock, "repl.wait_for_stream_position"):
            logger.info("Waiting for repl stream %r to reach %s", stream_name, position)
            await make_deferred_yieldable(deferred)
            logger.info(
                "Finished waiting for repl stream %r to reach %s", stream_name, position
            )
