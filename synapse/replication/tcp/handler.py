# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import Any, Dict, List, Set

from prometheus_client import Counter

from synapse.replication.tcp.commands import (
    PositionCommand,
    RdataCommand,
    RemoteServerUpCommand,
    SyncCommand,
)
from synapse.replication.tcp.streams import STREAMS_MAP, Stream

logger = logging.getLogger(__name__)


# number of updates received for each RDATA stream
inbound_rdata_count = Counter(
    "synapse_replication_tcp_protocol_inbound_rdata_count", "", ["stream_name"]
)


class ReplicationCommandHandler:
    """Handles incoming commands from replication.
    """

    def __init__(self, hs, handler):
        self.handler = handler

        # Set of streams that we're currently catching up with.
        self.streams_connecting = set()  # type: Set[str]

        self.streams = {
            stream.NAME: stream(hs) for stream in STREAMS_MAP.values()
        }  # type: Dict[str, Stream]

        # Map of stream to batched updates. See RdataCommand for info on how
        # batching works.
        self.pending_batches = {}  # type: Dict[str, List[Any]]

    async def on_RDATA(self, cmd: RdataCommand):
        stream_name = cmd.stream_name
        inbound_rdata_count.labels(stream_name).inc()

        try:
            row = STREAMS_MAP[stream_name].parse_row(cmd.row)
        except Exception:
            logger.exception("Failed to parse RDATA: %r %r", stream_name, cmd.row)
            raise

        if cmd.token is None or stream_name in self.streams_connecting:
            # I.e. this is part of a batch of updates for this stream. Batch
            # until we get an update for the stream with a non None token
            self.pending_batches.setdefault(stream_name, []).append(row)
        else:
            # Check if this is the last of a batch of updates
            rows = self.pending_batches.pop(stream_name, [])
            rows.append(row)
            await self.handler.on_rdata(stream_name, cmd.token, rows)

    async def on_POSITION(self, cmd: PositionCommand):
        stream = self.streams.get(cmd.stream_name)
        if not stream:
            logger.error("Got POSITION for unknown stream: %s", cmd.stream_name)
            return

        # We're about to go and catch up with the stream, so mark as connecting
        # to stop RDATA being handled at the same time.
        self.streams_connecting.add(cmd.stream_name)

        # Find where we previously streamed up to.
        current_token = self.handler.get_streams_to_replicate().get(cmd.stream_name)
        if current_token is None:
            logger.warning(
                "Got POSITION for stream we're not subscribed to: %s", cmd.stream_name
            )
            return

        # Fetch all updates between then and now.
        limited = True
        while limited:
            updates, current_token, limited = await stream.get_updates_since(
                current_token, cmd.token
            )
            if updates:
                await self.handler.on_rdata(
                    cmd.stream_name,
                    current_token,
                    [stream.parse_row(update[1]) for update in updates],
                )

        # We've now caught up to position sent to us, notify handler.
        await self.handler.on_position(cmd.stream_name, cmd.token)

        self.streams_connecting.discard(cmd.stream_name)

        # Handle any RDATA that came in while we were catching up.
        rows = self.pending_batches.pop(cmd.stream_name, [])
        if rows:
            await self.handler.on_rdata(cmd.stream_name, rows[-1].token, rows)

    async def on_SYNC(self, cmd: SyncCommand):
        self.handler.on_sync(cmd.data)

    async def on_REMOTE_SERVER_UP(self, cmd: RemoteServerUpCommand):
        self.handler.on_remote_server_up(cmd.data)

    def get_currently_syncing_users(self):
        """Get the list of currently syncing users (if any). This is called
        when a connection has been established and we need to send the
        currently syncing users. (Overriden by the synchrotron's only)
        """
        return self.handler.get_currently_syncing_users()

    def update_connection(self, connection):
        """Called when a connection has been established (or lost with None).
        """
        return self.handler.update_connection(connection)

    def finished_connecting(self):
        return self.handler.finished_connecting()
