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
from typing import Any, Callable, Dict, List

from prometheus_client import Counter

from synapse.metrics import LaterGauge
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
    UserIpCommand,
    UserSyncCommand,
)
from synapse.replication.tcp.streams import STREAMS_MAP, Stream

logger = logging.getLogger(__name__)


user_sync_counter = Counter("synapse_replication_tcp_resource_user_sync", "")
federation_ack_counter = Counter("synapse_replication_tcp_resource_federation_ack", "")
remove_pusher_counter = Counter("synapse_replication_tcp_resource_remove_pusher", "")
invalidate_cache_counter = Counter(
    "synapse_replication_tcp_resource_invalidate_cache", ""
)
user_ip_cache_counter = Counter("synapse_replication_tcp_resource_user_ip_cache", "")


class ReplicationClientHandler:
    """Handles incoming commands from replication.

    Proxies data to `HomeServer.get_replication_data_handler()`.
    """

    def __init__(self, hs):
        self.replication_data_handler = hs.get_replication_data_handler()
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self.clock = hs.get_clock()
        self.presence_handler = hs.get_presence_handler()
        self.instance_id = hs.get_instance_id()

        self.connections = []  # type: List[Any]

        self.streams = {
            stream.NAME: stream(hs) for stream in STREAMS_MAP.values()
        }  # type: Dict[str, Stream]

        LaterGauge(
            "synapse_replication_tcp_resource_total_connections",
            "",
            [],
            lambda: len(self.connections),
        )

        LaterGauge(
            "synapse_replication_tcp_resource_connections_per_stream",
            "",
            ["stream_name"],
            lambda: {
                (stream_name,): len(
                    [
                        conn
                        for conn in self.connections
                        if stream_name in conn.replication_streams
                    ]
                )
                for stream_name in self.streams
            },
        )

        # Map of stream to batched updates. See RdataCommand for info on how
        # batching works.
        self.pending_batches = {}  # type: Dict[str, List[Any]]

        self.is_master = hs.config.worker_app is None

        self.federation_sender = None
        if self.is_master and not hs.config.send_federation:
            self.federation_sender = hs.get_federation_sender()

        self._server_notices_sender = None
        if self.is_master:
            self._server_notices_sender = hs.get_server_notices_sender()
            self.notifier.add_remote_server_up_callback(self.send_remote_server_up)

    def new_connection(self, connection):
        self.connections.append(connection)

    def lost_connection(self, connection):
        try:
            self.connections.remove(connection)
        except ValueError:
            pass

    def connected(self) -> bool:
        """Do we have any replication connections open?

        Used to no-op if nothing is connected.
        """
        return bool(self.connections)

    async def on_REPLICATE(self, cmd: ReplicateCommand):
        # We only want to announce positions by the writer of the streams.
        # Currently this is just the master process.
        if not self.is_master:
            return

        if not self.connections:
            raise Exception("Not connected")

        for stream_name, stream in self.streams.items():
            current_token = stream.current_token()
            self.send_command(PositionCommand(stream_name, current_token))

    async def on_USER_SYNC(self, cmd: UserSyncCommand):
        user_sync_counter.inc()

        if self.is_master:
            await self.presence_handler.update_external_syncs_row(
                cmd.instance_id, cmd.user_id, cmd.is_syncing, cmd.last_sync_ms
            )

    async def on_CLEAR_USER_SYNC(self, cmd: ClearUserSyncsCommand):
        if self.is_master:
            await self.presence_handler.update_external_syncs_clear(cmd.instance_id)

    async def on_FEDERATION_ACK(self, cmd: FederationAckCommand):
        federation_ack_counter.inc()

        if self.federation_sender:
            self.federation_sender.federation_ack(cmd.token)

    async def on_REMOVE_PUSHER(self, cmd: RemovePusherCommand):
        remove_pusher_counter.inc()

        if self.is_master:
            await self.store.delete_pusher_by_app_id_pushkey_user_id(
                app_id=cmd.app_id, pushkey=cmd.push_key, user_id=cmd.user_id
            )

            self.notifier.on_new_replication_data()

    async def on_INVALIDATE_CACHE(self, cmd: InvalidateCacheCommand):
        invalidate_cache_counter.inc()

        if self.is_master:
            # We invalidate the cache locally, but then also stream that to other
            # workers.
            await self.store.invalidate_cache_and_stream(
                cmd.cache_func, tuple(cmd.keys)
            )

    async def on_USER_IP(self, cmd: UserIpCommand):
        user_ip_cache_counter.inc()

        if self.is_master:
            await self.store.insert_client_ip(
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

        try:
            row = STREAMS_MAP[stream_name].parse_row(cmd.row)
        except Exception:
            logger.exception("[%s] Failed to parse RDATA: %r", stream_name, cmd.row)
            raise

        if cmd.token is None:
            # I.e. this is part of a batch of updates for this stream. Batch
            # until we get an update for the stream with a non None token
            self.pending_batches.setdefault(stream_name, []).append(row)
        else:
            # Check if this is the last of a batch of updates
            rows = self.pending_batches.pop(stream_name, [])
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
        logger.info("Received rdata %s -> %s", stream_name, token)
        await self.replication_data_handler.on_rdata(stream_name, token, rows)

    async def on_POSITION(self, cmd: PositionCommand):
        stream = self.streams.get(cmd.stream_name)
        if not stream:
            logger.error("Got POSITION for unknown stream: %s", cmd.stream_name)
            return

        # Find where we previously streamed up to.
        current_token = self.replication_data_handler.get_streams_to_replicate().get(
            cmd.stream_name
        )
        if current_token is None:
            logger.debug(
                "Got POSITION for stream we're not subscribed to: %s", cmd.stream_name
            )
            return

        # Fetch all updates between then and now.
        limited = cmd.token != current_token
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
        await self.replication_data_handler.on_position(cmd.stream_name, cmd.token)

        # Handle any RDATA that came in while we were catching up.
        rows = self.pending_batches.pop(cmd.stream_name, [])
        if rows:
            await self.on_rdata(cmd.stream_name, rows[-1].token, rows)

    async def on_REMOTE_SERVER_UP(self, cmd: RemoteServerUpCommand):
        """Called when get a new REMOTE_SERVER_UP command."""
        if self.is_master:
            self.notifier.notify_remote_server_up(cmd.data)

    def get_currently_syncing_users(self):
        """Get the list of currently syncing users (if any). This is called
        when a connection has been established and we need to send the
        currently syncing users.
        """
        return self.presence_handler.get_currently_syncing_users()

    def send_command(self, cmd: Command):
        """Send a command to master (when we get establish a connection if we
        don't have one already.)
        """
        for conn in self.connections:
            conn.send_command(cmd)

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


class ReplicationDataHandler:
    """A replication data handler that simply discards all data.
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.typing_handler = hs.get_typing_handler()

        self.slaved_store = hs.config.worker_app is not None
        self.slaved_typing = not hs.config.server.handle_typing

    async def on_rdata(self, stream_name: str, token: int, rows: list):
        """Called to handle a batch of replication data with a given stream token.

        By default this just pokes the slave store. Can be overridden in subclasses to
        handle more.

        Args:
            stream_name (str): name of the replication stream for this batch of rows
            token (int): stream token for this batch of rows
            rows (list): a list of Stream.ROW_TYPE objects as returned by
                Stream.parse_row.
        """
        if self.slaved_store:
            self.store.process_replication_rows(stream_name, token, rows)

        if self.slaved_typing:
            self.typing_handler.process_replication_rows(stream_name, token, rows)

    def get_streams_to_replicate(self) -> Dict[str, int]:
        """Called when a new connection has been established and we need to
        subscribe to streams.

        Returns:
            map from stream name to the most recent update we have for
            that stream (ie, the point we want to start replicating from)
        """
        args = {}  # type: Dict[str, int]

        if self.slaved_store:
            args = self.store.stream_positions()
            user_account_data = args.pop("user_account_data", None)
            room_account_data = args.pop("room_account_data", None)
            if user_account_data:
                args["account_data"] = user_account_data
            elif room_account_data:
                args["account_data"] = room_account_data

        if self.slaved_typing:
            args.update(self.typing_handler.stream_positions())

        return args

    async def on_position(self, stream_name: str, token: int):
        if self.slaved_store:
            self.store.process_replication_rows(stream_name, token, [])

        if self.slaved_typing:
            self.typing_handler.process_replication_rows(stream_name, token, [])
