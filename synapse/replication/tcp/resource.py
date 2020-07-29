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
"""The server side of the replication stream.
"""

import logging
import random

from prometheus_client import Counter

from twisted.internet.protocol import Factory

from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.tcp.protocol import ServerReplicationStreamProtocol
from synapse.util.metrics import Measure

stream_updates_counter = Counter(
    "synapse_replication_tcp_resource_stream_updates", "", ["stream_name"]
)

logger = logging.getLogger(__name__)


class ReplicationStreamProtocolFactory(Factory):
    """Factory for new replication connections.
    """

    def __init__(self, hs):
        self.command_handler = hs.get_tcp_replication()
        self.clock = hs.get_clock()
        self.server_name = hs.config.server_name

        # If we've created a `ReplicationStreamProtocolFactory` then we're
        # almost certainly registering a replication listener, so let's ensure
        # that we've started a `ReplicationStreamer` instance to actually push
        # data.
        #
        # (This is a bit of a weird place to do this, but the alternatives such
        # as putting this in `HomeServer.setup()`, requires either passing the
        # listener config again or always starting a `ReplicationStreamer`.)
        hs.get_replication_streamer()

    def buildProtocol(self, addr):
        return ServerReplicationStreamProtocol(
            self.server_name, self.clock, self.command_handler
        )


class ReplicationStreamer(object):
    """Handles replication connections.

    This needs to be poked when new replication data may be available. When new
    data is available it will propagate to all connected clients.
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()
        self._instance_name = hs.get_instance_name()

        self._replication_torture_level = hs.config.replication_torture_level

        self.notifier.add_replication_callback(self.on_notifier_poke)

        # Keeps track of whether we are currently checking for updates
        self.is_looping = False
        self.pending_updates = False

        self.command_handler = hs.get_tcp_replication()

        # Set of streams to replicate.
        self.streams = self.command_handler.get_streams_to_replicate()

    def on_notifier_poke(self):
        """Checks if there is actually any new data and sends it to the
        connections if there are.

        This should get called each time new data is available, even if it
        is currently being executed, so that nothing gets missed
        """
        if not self.command_handler.connected():
            # Don't bother if nothing is listening. We still need to advance
            # the stream tokens otherwise they'll fall beihind forever
            for stream in self.streams:
                stream.discard_updates_and_advance()
            return

        self.pending_updates = True

        if self.is_looping:
            logger.debug("Notifier poke loop already running")
            return

        run_as_background_process("replication_notifier", self._run_notifier_loop)

    async def _run_notifier_loop(self):
        self.is_looping = True

        try:
            # Keep looping while there have been pokes about potential updates.
            # This protects against the race where a stream we already checked
            # gets an update while we're handling other streams.
            while self.pending_updates:
                self.pending_updates = False

                with Measure(self.clock, "repl.stream.get_updates"):
                    all_streams = self.streams

                    if self._replication_torture_level is not None:
                        # there is no guarantee about ordering between the streams,
                        # so let's shuffle them around a bit when we are in torture mode.
                        all_streams = list(all_streams)
                        random.shuffle(all_streams)

                    for stream in all_streams:
                        if stream.last_token == stream.current_token(
                            self._instance_name
                        ):
                            continue

                        if self._replication_torture_level:
                            await self.clock.sleep(
                                self._replication_torture_level / 1000.0
                            )

                        logger.debug(
                            "Getting stream: %s: %s -> %s",
                            stream.NAME,
                            stream.last_token,
                            stream.current_token(self._instance_name),
                        )
                        try:
                            updates, current_token, limited = await stream.get_updates()
                            self.pending_updates |= limited
                        except Exception:
                            logger.info("Failed to handle stream %s", stream.NAME)
                            raise

                        logger.debug(
                            "Sending %d updates", len(updates),
                        )

                        if updates:
                            logger.info(
                                "Streaming: %s -> %s", stream.NAME, updates[-1][0]
                            )
                            stream_updates_counter.labels(stream.NAME).inc(len(updates))

                        # Some streams return multiple rows with the same stream IDs,
                        # we need to make sure they get sent out in batches. We do
                        # this by setting the current token to all but the last of
                        # a series of updates with the same token to have a None
                        # token. See RdataCommand for more details.
                        batched_updates = _batch_updates(updates)

                        for token, row in batched_updates:
                            try:
                                self.command_handler.stream_update(
                                    stream.NAME, token, row
                                )
                            except Exception:
                                logger.exception("Failed to replicate")

            logger.debug("No more pending updates, breaking poke loop")
        finally:
            self.pending_updates = False
            self.is_looping = False


def _batch_updates(updates):
    """Takes a list of updates of form [(token, row)] and sets the token to
    None for all rows where the next row has the same token. This is used to
    implement batching.

    For example:

        [(1, _), (1, _), (2, _), (3, _), (3, _)]

    becomes:

        [(None, _), (1, _), (2, _), (None, _), (3, _)]
    """
    if not updates:
        return []

    new_updates = []
    for i, update in enumerate(updates[:-1]):
        if update[0] == updates[i + 1][0]:
            new_updates.append((None, update[1]))
        else:
            new_updates.append(update)

    new_updates.append(updates[-1])
    return new_updates
