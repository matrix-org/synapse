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
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple, TypeVar

from prometheus_client import Counter

from twisted.internet.protocol import ReconnectingClientFactory

from synapse.metrics import LaterGauge
from synapse.replication.tcp.client import DirectTcpReplicationClientFactory
from synapse.replication.tcp.commands import (
    ClearUserSyncsCommand,
    Command,
    FederationAckCommand,
    PositionCommand,
    RdataCommand,
    RemoteServerUpCommand,
    RemovePusherCommand,
    ReplicateCommand,
    UserIpCommand,
    UserSyncCommand,
)
from synapse.replication.tcp.protocol import AbstractConnection
from synapse.replication.tcp.streams import (
    STREAMS_MAP,
    BackfillStream,
    CachesStream,
    EventsStream,
    FederationStream,
    Stream,
)
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
        self._clock = hs.get_clock()
        self._instance_id = hs.get_instance_id()
        self._instance_name = hs.get_instance_name()

        self._streams = {
            stream.NAME: stream(hs) for stream in STREAMS_MAP.values()
        }  # type: Dict[str, Stream]

        # List of streams that this instance is the source of
        self._streams_to_replicate = []  # type: List[Stream]

        for stream in self._streams.values():
            if stream.NAME == CachesStream.NAME:
                # All workers can write to the cache invalidation stream.
                self._streams_to_replicate.append(stream)
                continue

            if isinstance(stream, (EventsStream, BackfillStream)):
                # Only add EventStream and BackfillStream as a source on the
                # instance in charge of event persistence.
                if hs.config.worker.writers.events == hs.get_instance_name():
                    self._streams_to_replicate.append(stream)

                continue

            # Only add any other streams if we're on master.
            if hs.config.worker_app is not None:
                continue

            if stream.NAME == FederationStream.NAME and hs.config.send_federation:
                # We only support federation stream if federation sending
                # has been disabled on the master.
                continue

            self._streams_to_replicate.append(stream)

        self._position_linearizer = Linearizer(
            "replication_position", clock=self._clock
        )

        # Map of stream to batched updates. See RdataCommand for info on how
        # batching works.
        self._pending_batches = {}  # type: Dict[str, List[Any]]

        # The factory used to create connections.
        self._factory = None  # type: Optional[ReconnectingClientFactory]

        # The currently connected connections. (The list of places we need to send
        # outgoing replication commands to.)
        self._connections = []  # type: List[AbstractConnection]

        # For each connection, the incoming streams that are coming from that connection
        self._streams_by_connection = {}  # type: Dict[AbstractConnection, Set[str]]

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

    def start_replication(self, hs):
        """Helper method to start a replication connection to the remote server
        using TCP.
        """
        if hs.config.redis.redis_enabled:
            from synapse.replication.tcp.redis import (
                RedisDirectTcpReplicationClientFactory,
            )
            import txredisapi

            logger.info(
                "Connecting to redis (host=%r port=%r)",
                hs.config.redis_host,
                hs.config.redis_port,
            )

            # First let's ensure that we have a ReplicationStreamer started.
            hs.get_replication_streamer()

            # We need two connections to redis, one for the subscription stream and
            # one to send commands to (as you can't send further redis commands to a
            # connection after SUBSCRIBE is called).

            # First create the connection for sending commands.
            outbound_redis_connection = txredisapi.lazyConnection(
                host=hs.config.redis_host,
                port=hs.config.redis_port,
                password=hs.config.redis.redis_password,
                reconnect=True,
            )

            # Now create the factory/connection for the subscription stream.
            self._factory = RedisDirectTcpReplicationClientFactory(
                hs, outbound_redis_connection
            )
            hs.get_reactor().connectTCP(
                hs.config.redis.redis_host, hs.config.redis.redis_port, self._factory,
            )
        else:
            client_name = hs.get_instance_name()
            self._factory = DirectTcpReplicationClientFactory(hs, client_name, self)
            host = hs.config.worker_replication_host
            port = hs.config.worker_replication_port
            hs.get_reactor().connectTCP(host, port, self._factory)

    def get_streams(self) -> Dict[str, Stream]:
        """Get a map from stream name to all streams.
        """
        return self._streams

    def get_streams_to_replicate(self) -> List[Stream]:
        """Get a list of streams that this instances replicates.
        """
        return self._streams_to_replicate

    async def on_REPLICATE(self, conn: AbstractConnection, cmd: ReplicateCommand):
        self.send_positions_to_connection(conn)

    def send_positions_to_connection(self, conn: AbstractConnection):
        """Send current position of all streams this process is source of to
        the connection.
        """

        # We respond with current position of all streams this instance
        # replicates.
        for stream in self.get_streams_to_replicate():
            self.send_command(
                PositionCommand(
                    stream.NAME,
                    self._instance_name,
                    stream.current_token(self._instance_name),
                )
            )

    async def on_USER_SYNC(self, conn: AbstractConnection, cmd: UserSyncCommand):
        user_sync_counter.inc()

        if self._is_master:
            await self._presence_handler.update_external_syncs_row(
                cmd.instance_id, cmd.user_id, cmd.is_syncing, cmd.last_sync_ms
            )

    async def on_CLEAR_USER_SYNC(
        self, conn: AbstractConnection, cmd: ClearUserSyncsCommand
    ):
        if self._is_master:
            await self._presence_handler.update_external_syncs_clear(cmd.instance_id)

    async def on_FEDERATION_ACK(
        self, conn: AbstractConnection, cmd: FederationAckCommand
    ):
        federation_ack_counter.inc()

        if self._federation_sender:
            self._federation_sender.federation_ack(cmd.token)

    async def on_REMOVE_PUSHER(
        self, conn: AbstractConnection, cmd: RemovePusherCommand
    ):
        remove_pusher_counter.inc()

        if self._is_master:
            await self._store.delete_pusher_by_app_id_pushkey_user_id(
                app_id=cmd.app_id, pushkey=cmd.push_key, user_id=cmd.user_id
            )

            self._notifier.on_new_replication_data()

    async def on_USER_IP(self, conn: AbstractConnection, cmd: UserIpCommand):
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

    async def on_RDATA(self, conn: AbstractConnection, cmd: RdataCommand):
        if cmd.instance_name == self._instance_name:
            # Ignore RDATA that are just our own echoes
            return

        stream_name = cmd.stream_name
        inbound_rdata_count.labels(stream_name).inc()

        try:
            row = STREAMS_MAP[stream_name].parse_row(cmd.row)
        except Exception:
            logger.exception("Failed to parse RDATA: %r %r", stream_name, cmd.row)
            raise

        # We linearize here for two reasons:
        #   1. so we don't try and concurrently handle multiple rows for the
        #      same stream, and
        #   2. so we don't race with getting a POSITION command and fetching
        #      missing RDATA.
        with await self._position_linearizer.queue(cmd.stream_name):
            # make sure that we've processed a POSITION for this stream *on this
            # connection*. (A POSITION on another connection is no good, as there
            # is no guarantee that we have seen all the intermediate updates.)
            sbc = self._streams_by_connection.get(conn)
            if not sbc or stream_name not in sbc:
                # Let's drop the row for now, on the assumption we'll receive a
                # `POSITION` soon and we'll catch up correctly then.
                logger.debug(
                    "Discarding RDATA for unconnected stream %s -> %s",
                    stream_name,
                    cmd.token,
                )
                return

            if cmd.token is None:
                # I.e. this is part of a batch of updates for this stream (in
                # which case batch until we get an update for the stream with a non
                # None token).
                self._pending_batches.setdefault(stream_name, []).append(row)
            else:
                # Check if this is the last of a batch of updates
                rows = self._pending_batches.pop(stream_name, [])
                rows.append(row)
                await self.on_rdata(stream_name, cmd.instance_name, cmd.token, rows)

    async def on_rdata(
        self, stream_name: str, instance_name: str, token: int, rows: list
    ):
        """Called to handle a batch of replication data with a given stream token.

        Args:
            stream_name: name of the replication stream for this batch of rows
            instance_name: the instance that wrote the rows.
            token: stream token for this batch of rows
            rows: a list of Stream.ROW_TYPE objects as returned by
                Stream.parse_row.
        """
        logger.debug("Received rdata %s (%s) -> %s", stream_name, instance_name, token)
        await self._replication_data_handler.on_rdata(
            stream_name, instance_name, token, rows
        )

    async def on_POSITION(self, conn: AbstractConnection, cmd: PositionCommand):
        if cmd.instance_name == self._instance_name:
            # Ignore POSITION that are just our own echoes
            return

        logger.info("Handling '%s %s'", cmd.NAME, cmd.to_line())

        stream_name = cmd.stream_name
        stream = self._streams.get(stream_name)
        if not stream:
            logger.error("Got POSITION for unknown stream: %s", stream_name)
            return

        # We protect catching up with a linearizer in case the replication
        # connection reconnects under us.
        with await self._position_linearizer.queue(stream_name):
            # We're about to go and catch up with the stream, so remove from set
            # of connected streams.
            for streams in self._streams_by_connection.values():
                streams.discard(stream_name)

            # We clear the pending batches for the stream as the fetching of the
            # missing updates below will fetch all rows in the batch.
            self._pending_batches.pop(stream_name, [])

            # Find where we previously streamed up to.
            current_token = stream.current_token(cmd.instance_name)

            # If the position token matches our current token then we're up to
            # date and there's nothing to do. Otherwise, fetch all updates
            # between then and now.
            missing_updates = cmd.token != current_token
            while missing_updates:
                logger.info(
                    "Fetching replication rows for '%s' between %i and %i",
                    stream_name,
                    current_token,
                    cmd.token,
                )
                (
                    updates,
                    current_token,
                    missing_updates,
                ) = await stream.get_updates_since(
                    cmd.instance_name, current_token, cmd.token
                )

                # TODO: add some tests for this

                # Some streams return multiple rows with the same stream IDs,
                # which need to be processed in batches.

                for token, rows in _batch_updates(updates):
                    await self.on_rdata(
                        stream_name,
                        cmd.instance_name,
                        token,
                        [stream.parse_row(row) for row in rows],
                    )

            logger.info("Caught up with stream '%s' to %i", stream_name, cmd.token)

            # We've now caught up to position sent to us, notify handler.
            await self._replication_data_handler.on_position(
                cmd.stream_name, cmd.instance_name, cmd.token
            )

            self._streams_by_connection.setdefault(conn, set()).add(stream_name)

    async def on_REMOTE_SERVER_UP(
        self, conn: AbstractConnection, cmd: RemoteServerUpCommand
    ):
        """"Called when get a new REMOTE_SERVER_UP command."""
        self._replication_data_handler.on_remote_server_up(cmd.data)

        self._notifier.notify_remote_server_up(cmd.data)

        # We relay to all other connections to ensure every instance gets the
        # notification.
        #
        # When configured to use redis we'll always only have one connection and
        # so this is a no-op (all instances will have already received the same
        # REMOTE_SERVER_UP command).
        #
        # For direct TCP connections this will relay to all other connections
        # connected to us. When on master this will correctly fan out to all
        # other direct TCP clients and on workers there'll only be the one
        # connection to master.
        #
        # (The logic here should also be sound if we have a mix of Redis and
        # direct TCP connections so long as there is only one traffic route
        # between two instances, but that is not currently supported).
        self.send_command(cmd, ignore_conn=conn)

    def new_connection(self, connection: AbstractConnection):
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

        # Tell the other end if we have any users currently syncing.
        currently_syncing = (
            self._presence_handler.get_currently_syncing_users_for_replication()
        )

        now = self._clock.time_msec()
        for user_id in currently_syncing:
            connection.send_command(
                UserSyncCommand(self._instance_id, user_id, True, now)
            )

    def lost_connection(self, connection: AbstractConnection):
        """Called when a connection is closed/lost.
        """
        # we no longer need _streams_by_connection for this connection.
        streams = self._streams_by_connection.pop(connection, None)
        if streams:
            logger.info(
                "Lost replication connection; streams now disconnected: %s", streams
            )
        try:
            self._connections.remove(connection)
        except ValueError:
            pass

    def connected(self) -> bool:
        """Do we have any replication connections open?

        Is used by e.g. `ReplicationStreamer` to no-op if nothing is connected.
        """
        return bool(self._connections)

    def send_command(
        self, cmd: Command, ignore_conn: Optional[AbstractConnection] = None
    ):
        """Send a command to all connected connections.

        Args:
            cmd
            ignore_conn: If set don't send command to the given connection.
                Used when relaying commands from one connection to all others.
        """
        if self._connections:
            for connection in self._connections:
                if connection == ignore_conn:
                    continue

                try:
                    connection.send_command(cmd)
                except Exception:
                    # We probably want to catch some types of exceptions here
                    # and log them as warnings (e.g. connection gone), but I
                    # can't find what those exception types they would be.
                    logger.exception(
                        "Failed to write command %s to connection %s",
                        cmd.NAME,
                        connection,
                    )
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
        self.send_command(RdataCommand(stream_name, self._instance_name, token, data))


UpdateToken = TypeVar("UpdateToken")
UpdateRow = TypeVar("UpdateRow")


def _batch_updates(
    updates: Iterable[Tuple[UpdateToken, UpdateRow]]
) -> Iterator[Tuple[UpdateToken, List[UpdateRow]]]:
    """Collect stream updates with the same token together

    Given a series of updates returned by Stream.get_updates_since(), collects
    the updates which share the same stream_id together.

    For example:

        [(1, a), (1, b), (2, c), (3, d), (3, e)]

    becomes:

        [
            (1, [a, b]),
            (2, [c]),
            (3, [d, e]),
        ]
    """

    update_iter = iter(updates)

    first_update = next(update_iter, None)
    if first_update is None:
        # empty input
        return

    current_batch_token = first_update[0]
    current_batch = [first_update[1]]

    for token, row in update_iter:
        if token != current_batch_token:
            # different token to the previous row: flush the previous
            # batch and start anew
            yield current_batch_token, current_batch
            current_batch_token = token
            current_batch = []

        current_batch.append(row)

    # flush the final batch
    yield current_batch_token, current_batch
