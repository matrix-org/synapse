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

import logging
from typing import Any, Callable, Dict, List, Optional, Set

from prometheus_client import Counter

from synapse.metrics import LaterGauge
from synapse.replication.tcp.client import ReplicationClientFactory
from synapse.replication.tcp.commands import (
    ClearUserSyncsCommand,
    Command,
    FederationAckCommand,
    InvalidateCacheCommand,
    PositionCommand,
    RdataCommand,
    RemoteServerUpCommand,
    RemovePusherCommand,
    ReplicateCommand,
    SyncCommand,
    UserIpCommand,
    UserSyncCommand,
)
from synapse.replication.tcp.streams import STREAMS_MAP, Stream
from synapse.util.async_helpers import Linearizer

logger = logging.getLogger(__name__)


# number of updates received for each RDATA stream
inbound_rdata_count = Counter(
    "synapse_replication_tcp_protocol_inbound_rdata_count", "", ["stream_name"]
)
user_sync_counter = Counter("synapse_replication_tcp_resource_user_sync", "")
federation_ack_counter = Counter("synapse_replication_tcp_resource_federation_ack", "")
remove_pusher_counter = Counter("synapse_replication_tcp_resource_remove_pusher", "")
invalidate_cache_counter = Counter(
    "synapse_replication_tcp_resource_invalidate_cache", ""
)
user_ip_cache_counter = Counter("synapse_replication_tcp_resource_user_ip_cache", "")


class ReplicationCommandHandler:
    """Handles incoming commands from replication as well as sending commands
    back out to connections.
    """

    def __init__(self, hs):
        self._replication_data_handler = hs.get_replication_data_handler()
        self._presence_handler = hs.get_presence_handler()
        self._store = hs.get_datastore()
        self._notifier = hs.get_notifier()

        # Set of streams that we've caught up with.
        self._streams_connected = set()  # type: Set[str]

        self._streams = {
            stream.NAME: stream(hs) for stream in STREAMS_MAP.values()
        }  # type: Dict[str, Stream]

        self._position_linearizer = Linearizer("replication_position")

        # Map of stream to batched updates. See RdataCommand for info on how
        # batching works.
        self._pending_batches = {}  # type: Dict[str, List[Any]]

        # The factory used to create connections.
        self._factory = None  # type: Optional[ReplicationClientFactory]

        # The currently connected connections.
        self._connections = []  # type: List[Any]

        LaterGauge(
            "synapse_replication_tcp_resource_total_connections",
            "",
            [],
            lambda: len(self._connections),
        )

        self._is_master = hs.config.worker_app is None

        self._federation_sender = None
        if self._is_master and not hs.config.send_federation:
            self._federation_sender = hs.get_federation_sender()

        self._server_notices_sender = None
        if self._is_master:
            self._server_notices_sender = hs.get_server_notices_sender()
            self._notifier.add_remote_server_up_callback(self.send_remote_server_up)

    def start_replication(self, hs):
        """Helper method to start a replication connection to the remote server
        using TCP.
        """
        client_name = hs.config.worker_name
        self._factory = ReplicationClientFactory(hs, client_name, self)
        host = hs.config.worker_replication_host
        port = hs.config.worker_replication_port
        hs.get_reactor().connectTCP(host, port, self._factory)

    async def on_REPLICATE(self, cmd: ReplicateCommand):
        # We only want to announce positions by the writer of the streams.
        # Currently this is just the master process.
        if not self._is_master:
            return

        for stream_name, stream in self._streams.items():
            current_token = stream.current_token()
            self.send_command(PositionCommand(stream_name, current_token))

    async def on_USER_SYNC(self, cmd: UserSyncCommand):
        user_sync_counter.inc()

        if self._is_master:
            await self._presence_handler.update_external_syncs_row(
                cmd.instance_id, cmd.user_id, cmd.is_syncing, cmd.last_sync_ms
            )

    async def on_CLEAR_USER_SYNC(self, cmd: ClearUserSyncsCommand):
        if self._is_master:
            await self._presence_handler.update_external_syncs_clear(cmd.instance_id)

    async def on_FEDERATION_ACK(self, cmd: FederationAckCommand):
        federation_ack_counter.inc()

        if self._federation_sender:
            self._federation_sender.federation_ack(cmd.token)

    async def on_REMOVE_PUSHER(self, cmd: RemovePusherCommand):
        remove_pusher_counter.inc()

        if self._is_master:
            await self._store.delete_pusher_by_app_id_pushkey_user_id(
                app_id=cmd.app_id, pushkey=cmd.push_key, user_id=cmd.user_id
            )

            self._notifier.on_new_replication_data()

    async def on_INVALIDATE_CACHE(self, cmd: InvalidateCacheCommand):
        invalidate_cache_counter.inc()

        if self._is_master:
            # We invalidate the cache locally, but then also stream that to other
            # workers.
            await self._store.invalidate_cache_and_stream(
                cmd.cache_func, tuple(cmd.keys)
            )

    async def on_USER_IP(self, cmd: UserIpCommand):
        user_ip_cache_counter.inc()

        if self._is_master:
            await self._store.insert_client_ip(
                cmd.user_id,
                cmd.access_token,
                cmd.ip,
                cmd.user_agent,
                cmd.device_id,
                cmd.last_seen,
            )

        if self._server_notices_sender:
            await self._server_notices_sender.on_user_ip(cmd.user_id)

    async def on_RDATA(self, cmd: RdataCommand):
        stream_name = cmd.stream_name
        inbound_rdata_count.labels(stream_name).inc()

        try:
            row = STREAMS_MAP[stream_name].parse_row(cmd.row)
        except Exception:
            logger.exception("Failed to parse RDATA: %r %r", stream_name, cmd.row)
            raise

        if cmd.token is None or stream_name not in self._streams_connected:
            # I.e. either this is part of a batch of updates for this stream (in
            # which case batch until we get an update for the stream with a non
            # None token) or we're currently connecting so we queue up rows.
            self._pending_batches.setdefault(stream_name, []).append(row)
        else:
            # Check if this is the last of a batch of updates
            rows = self._pending_batches.pop(stream_name, [])
            rows.append(row)
            await self.on_rdata(stream_name, cmd.token, rows)

    async def on_rdata(self, stream_name: str, token: int, rows: list):
        """Called to handle a batch of replication data with a given stream token.

        Args:
            stream_name: name of the replication stream for this batch of rows
            token: stream token for this batch of rows
            rows: a list of Stream.ROW_TYPE objects as returned by
                Stream.parse_row.
        """
        logger.debug("Received rdata %s -> %s", stream_name, token)
        await self._replication_data_handler.on_rdata(stream_name, token, rows)

    async def on_POSITION(self, cmd: PositionCommand):
        stream = self._streams.get(cmd.stream_name)
        if not stream:
            logger.error("Got POSITION for unknown stream: %s", cmd.stream_name)
            return

        # We protect catching up with a linearizer in case the replication
        # connection reconnects under us.
        with await self._position_linearizer.queue(cmd.stream_name):
            # We're about to go and catch up with the stream, so mark as connecting
            # to stop RDATA being handled at the same time by removing stream from
            # list of connected streams. We also clear any batched up RDATA from
            # before we got the POSITION.
            self._streams_connected.discard(cmd.stream_name)
            self._pending_batches.clear()

            # Find where we previously streamed up to.
            current_token = self._replication_data_handler.get_streams_to_replicate().get(
                cmd.stream_name
            )
            if current_token is None:
                logger.warning(
                    "Got POSITION for stream we're not subscribed to: %s",
                    cmd.stream_name,
                )
                return

            # Fetch all updates between then and now.
            limited = True
            while limited:
                updates, current_token, limited = await stream.get_updates_since(
                    current_token, cmd.token
                )
                if updates:
                    await self.on_rdata(
                        cmd.stream_name,
                        current_token,
                        [stream.parse_row(update[1]) for update in updates],
                    )

            # We've now caught up to position sent to us, notify handler.
            await self._replication_data_handler.on_position(cmd.stream_name, cmd.token)

            # Handle any RDATA that came in while we were catching up.
            rows = self._pending_batches.pop(cmd.stream_name, [])
            if rows:
                await self._replication_data_handler.on_rdata(
                    cmd.stream_name, rows[-1].token, rows
                )

            self._streams_connected.add(cmd.stream_name)

    async def on_SYNC(self, cmd: SyncCommand):
        pass

    async def on_REMOTE_SERVER_UP(self, cmd: RemoteServerUpCommand):
        """"Called when get a new REMOTE_SERVER_UP command."""
        self._replication_data_handler.on_remote_server_up(cmd.data)

        if self._is_master:
            self._notifier.notify_remote_server_up(cmd.data)

    def get_currently_syncing_users(self):
        """Get the list of currently syncing users (if any). This is called
        when a connection has been established and we need to send the
        currently syncing users.
        """
        return self._presence_handler.get_currently_syncing_users()

    def new_connection(self, connection):
        """Called when we have a new connection.
        """
        self._connections.append(connection)

        # If we are connected to replication as a client (rather than a server)
        # we need to reset the reconnection delay on the client factory (which
        # is used to do exponential back off when the connection drops).
        #
        # Ideally we would reset the delay when we've "fully established" the
        # connection (for some definition thereof) to stop us from tightlooping
        # on reconnection if something fails after this point and we drop the
        # connection. Unfortunately, we don't really have a better definition of
        # "fully established" than the connection being established.
        if self._factory:
            self._factory.resetDelay()

    def lost_connection(self, connection):
        """Called when a connection is closed/lost.
        """
        try:
            self._connections.remove(connection)
        except ValueError:
            pass

    def connected(self) -> bool:
        """Do we have any replication connections open?

        Is used by e.g. `ReplicationStreamer` to no-op if nothing is connected.
        """
        return bool(self._connections)

    def send_command(self, cmd: Command):
        """Send a command to all connected connections.
        """
        if self._connections:
            for connection in self._connections:
                connection.send_command(cmd)
        else:
            logger.warning("Dropping command as not connected: %r", cmd.NAME)

    def send_federation_ack(self, token: int):
        """Ack data for the federation stream. This allows the master to drop
        data stored purely in memory.
        """
        self.send_command(FederationAckCommand(token))

    def send_user_sync(
        self, instance_id: str, user_id: str, is_syncing: bool, last_sync_ms: int
    ):
        """Poke the master that a user has started/stopped syncing.
        """
        self.send_command(
            UserSyncCommand(instance_id, user_id, is_syncing, last_sync_ms)
        )

    def send_remove_pusher(self, app_id: str, push_key: str, user_id: str):
        """Poke the master to remove a pusher for a user
        """
        cmd = RemovePusherCommand(app_id, push_key, user_id)
        self.send_command(cmd)

    def send_invalidate_cache(self, cache_func: Callable, keys: tuple):
        """Poke the master to invalidate a cache.
        """
        cmd = InvalidateCacheCommand(cache_func.__name__, keys)
        self.send_command(cmd)

    def send_user_ip(
        self,
        user_id: str,
        access_token: str,
        ip: str,
        user_agent: str,
        device_id: str,
        last_seen: int,
    ):
        """Tell the master that the user made a request.
        """
        cmd = UserIpCommand(user_id, access_token, ip, user_agent, device_id, last_seen)
        self.send_command(cmd)

    def send_remote_server_up(self, server: str):
        self.send_command(RemoteServerUpCommand(server))

    def stream_update(self, stream_name: str, token: str, data: Any):
        """Called when a new update is available to stream to clients.

        We need to check if the client is interested in the stream or not
        """
        self.send_command(RdataCommand(stream_name, token, data))
