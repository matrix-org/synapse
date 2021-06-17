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
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

from prometheus_client import Counter
from typing_extensions import Deque

from twisted.internet.protocol import ReconnectingClientFactory

from synapse.metrics import LaterGauge
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.tcp.client import DirectTcpReplicationClientFactory
from synapse.replication.tcp.commands import (
    ClearUserSyncsCommand,
    Command,
    FederationAckCommand,
    PositionCommand,
    RdataCommand,
    RemoteServerUpCommand,
    ReplicateCommand,
    UserIpCommand,
    UserSyncCommand,
)
from synapse.replication.tcp.protocol import IReplicationConnection
from synapse.replication.tcp.streams import (
    STREAMS_MAP,
    AccountDataStream,
    BackfillStream,
    CachesStream,
    EventsStream,
    FederationStream,
    PresenceFederationStream,
    PresenceStream,
    ReceiptsStream,
    Stream,
    TagAccountDataStream,
    ToDeviceStream,
    TypingStream,
)

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# number of updates received for each RDATA stream
inbound_rdata_count = Counter(
    "synapse_replication_tcp_protocol_inbound_rdata_count", "", ["stream_name"]
)
user_sync_counter = Counter("synapse_replication_tcp_resource_user_sync", "")
federation_ack_counter = Counter("synapse_replication_tcp_resource_federation_ack", "")
remove_pusher_counter = Counter("synapse_replication_tcp_resource_remove_pusher", "")

user_ip_cache_counter = Counter("synapse_replication_tcp_resource_user_ip_cache", "")


# the type of the entries in _command_queues_by_stream
_StreamCommandQueue = Deque[
    Tuple[Union[RdataCommand, PositionCommand], IReplicationConnection]
]


class ReplicationCommandHandler:
    """Handles incoming commands from replication as well as sending commands
    back out to connections.
    """

    def __init__(self, hs: "HomeServer"):
        self._replication_data_handler = hs.get_replication_data_handler()
        self._presence_handler = hs.get_presence_handler()
        self._store = hs.get_datastore()
        self._notifier = hs.get_notifier()
        self._clock = hs.get_clock()
        self._instance_id = hs.get_instance_id()
        self._instance_name = hs.get_instance_name()

        self._is_presence_writer = (
            hs.get_instance_name() in hs.config.worker.writers.presence
        )

        self._streams = {
            stream.NAME: stream(hs) for stream in STREAMS_MAP.values()
        }  # type: Dict[str, Stream]

        # List of streams that this instance is the source of
        self._streams_to_replicate = []  # type: List[Stream]

        for stream in self._streams.values():
            if hs.config.redis.redis_enabled and stream.NAME == CachesStream.NAME:
                # All workers can write to the cache invalidation stream when
                # using redis.
                self._streams_to_replicate.append(stream)
                continue

            if isinstance(stream, (EventsStream, BackfillStream)):
                # Only add EventStream and BackfillStream as a source on the
                # instance in charge of event persistence.
                if hs.get_instance_name() in hs.config.worker.writers.events:
                    self._streams_to_replicate.append(stream)

                continue

            if isinstance(stream, ToDeviceStream):
                # Only add ToDeviceStream as a source on instances in charge of
                # sending to device messages.
                if hs.get_instance_name() in hs.config.worker.writers.to_device:
                    self._streams_to_replicate.append(stream)

                continue

            if isinstance(stream, TypingStream):
                # Only add TypingStream as a source on the instance in charge of
                # typing.
                if hs.config.worker.writers.typing == hs.get_instance_name():
                    self._streams_to_replicate.append(stream)

                continue

            if isinstance(stream, (AccountDataStream, TagAccountDataStream)):
                # Only add AccountDataStream and TagAccountDataStream as a source on the
                # instance in charge of account_data persistence.
                if hs.get_instance_name() in hs.config.worker.writers.account_data:
                    self._streams_to_replicate.append(stream)

                continue

            if isinstance(stream, ReceiptsStream):
                # Only add ReceiptsStream as a source on the instance in charge of
                # receipts.
                if hs.get_instance_name() in hs.config.worker.writers.receipts:
                    self._streams_to_replicate.append(stream)

                continue

            if isinstance(stream, (PresenceStream, PresenceFederationStream)):
                # Only add PresenceStream as a source on the instance in charge
                # of presence.
                if self._is_presence_writer:
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

        # Map of stream name to batched updates. See RdataCommand for info on
        # how batching works.
        self._pending_batches = {}  # type: Dict[str, List[Any]]

        # The factory used to create connections.
        self._factory = None  # type: Optional[ReconnectingClientFactory]

        # The currently connected connections. (The list of places we need to send
        # outgoing replication commands to.)
        self._connections = []  # type: List[IReplicationConnection]

        LaterGauge(
            "synapse_replication_tcp_resource_total_connections",
            "",
            [],
            lambda: len(self._connections),
        )

        # When POSITION or RDATA commands arrive, we stick them in a queue and process
        # them in order in a separate background process.

        # the streams which are currently being processed by _unsafe_process_queue
        self._processing_streams = set()  # type: Set[str]

        # for each stream, a queue of commands that are awaiting processing, and the
        # connection that they arrived on.
        self._command_queues_by_stream = {
            stream_name: _StreamCommandQueue() for stream_name in self._streams
        }

        # For each connection, the incoming stream names that have received a POSITION
        # from that connection.
        self._streams_by_connection = {}  # type: Dict[IReplicationConnection, Set[str]]

        LaterGauge(
            "synapse_replication_tcp_command_queue",
            "Number of inbound RDATA/POSITION commands queued for processing",
            ["stream_name"],
            lambda: {
                (stream_name,): len(queue)
                for stream_name, queue in self._command_queues_by_stream.items()
            },
        )

        self._is_master = hs.config.worker_app is None

        self._federation_sender = None
        if self._is_master and not hs.config.send_federation:
            self._federation_sender = hs.get_federation_sender()

        self._server_notices_sender = None
        if self._is_master:
            self._server_notices_sender = hs.get_server_notices_sender()

    def _add_command_to_stream_queue(
        self, conn: IReplicationConnection, cmd: Union[RdataCommand, PositionCommand]
    ) -> None:
        """Queue the given received command for processing

        Adds the given command to the per-stream queue, and processes the queue if
        necessary
        """
        stream_name = cmd.stream_name
        queue = self._command_queues_by_stream.get(stream_name)
        if queue is None:
            logger.error("Got %s for unknown stream: %s", cmd.NAME, stream_name)
            return

        queue.append((cmd, conn))

        # if we're already processing this stream, there's nothing more to do:
        # the new entry on the queue will get picked up in due course
        if stream_name in self._processing_streams:
            return

        # fire off a background process to start processing the queue.
        run_as_background_process(
            "process-replication-data", self._unsafe_process_queue, stream_name
        )

    async def _unsafe_process_queue(self, stream_name: str):
        """Processes the command queue for the given stream, until it is empty

        Does not check if there is already a thread processing the queue, hence "unsafe"
        """
        assert stream_name not in self._processing_streams

        self._processing_streams.add(stream_name)
        try:
            queue = self._command_queues_by_stream.get(stream_name)
            while queue:
                cmd, conn = queue.popleft()
                try:
                    await self._process_command(cmd, conn, stream_name)
                except Exception:
                    logger.exception("Failed to handle command %s", cmd)
        finally:
            self._processing_streams.discard(stream_name)

    async def _process_command(
        self,
        cmd: Union[PositionCommand, RdataCommand],
        conn: IReplicationConnection,
        stream_name: str,
    ) -> None:
        if isinstance(cmd, PositionCommand):
            await self._process_position(stream_name, conn, cmd)
        elif isinstance(cmd, RdataCommand):
            await self._process_rdata(stream_name, conn, cmd)
        else:
            # This shouldn't be possible
            raise Exception("Unrecognised command %s in stream queue", cmd.NAME)

    def start_replication(self, hs):
        """Helper method to start a replication connection to the remote server
        using TCP.
        """
        if hs.config.redis.redis_enabled:
            from synapse.replication.tcp.redis import (
                RedisDirectTcpReplicationClientFactory,
            )

            # First let's ensure that we have a ReplicationStreamer started.
            hs.get_replication_streamer()

            # We need two connections to redis, one for the subscription stream and
            # one to send commands to (as you can't send further redis commands to a
            # connection after SUBSCRIBE is called).

            # First create the connection for sending commands.
            outbound_redis_connection = hs.get_outbound_redis_connection()

            # Now create the factory/connection for the subscription stream.
            self._factory = RedisDirectTcpReplicationClientFactory(
                hs, outbound_redis_connection
            )
            hs.get_reactor().connectTCP(
                hs.config.redis.redis_host.encode(),
                hs.config.redis.redis_port,
                self._factory,
            )
        else:
            client_name = hs.get_instance_name()
            self._factory = DirectTcpReplicationClientFactory(hs, client_name, self)
            host = hs.config.worker_replication_host
            port = hs.config.worker_replication_port
            hs.get_reactor().connectTCP(host.encode(), port, self._factory)

    def get_streams(self) -> Dict[str, Stream]:
        """Get a map from stream name to all streams."""
        return self._streams

    def get_streams_to_replicate(self) -> List[Stream]:
        """Get a list of streams that this instances replicates."""
        return self._streams_to_replicate

    def on_REPLICATE(self, conn: IReplicationConnection, cmd: ReplicateCommand):
        self.send_positions_to_connection(conn)

    def send_positions_to_connection(self, conn: IReplicationConnection):
        """Send current position of all streams this process is source of to
        the connection.
        """

        # We respond with current position of all streams this instance
        # replicates.
        for stream in self.get_streams_to_replicate():
            # Note that we use the current token as the prev token here (rather
            # than stream.last_token), as we can't be sure that there have been
            # no rows written between last token and the current token (since we
            # might be racing with the replication sending bg process).
            current_token = stream.current_token(self._instance_name)
            self.send_command(
                PositionCommand(
                    stream.NAME,
                    self._instance_name,
                    current_token,
                    current_token,
                )
            )

    def on_USER_SYNC(
        self, conn: IReplicationConnection, cmd: UserSyncCommand
    ) -> Optional[Awaitable[None]]:
        user_sync_counter.inc()

        if self._is_presence_writer:
            return self._presence_handler.update_external_syncs_row(
                cmd.instance_id, cmd.user_id, cmd.is_syncing, cmd.last_sync_ms
            )
        else:
            return None

    def on_CLEAR_USER_SYNC(
        self, conn: IReplicationConnection, cmd: ClearUserSyncsCommand
    ) -> Optional[Awaitable[None]]:
        if self._is_presence_writer:
            return self._presence_handler.update_external_syncs_clear(cmd.instance_id)
        else:
            return None

    def on_FEDERATION_ACK(
        self, conn: IReplicationConnection, cmd: FederationAckCommand
    ):
        federation_ack_counter.inc()

        if self._federation_sender:
            self._federation_sender.federation_ack(cmd.instance_name, cmd.token)

    def on_USER_IP(
        self, conn: IReplicationConnection, cmd: UserIpCommand
    ) -> Optional[Awaitable[None]]:
        user_ip_cache_counter.inc()

        if self._is_master:
            return self._handle_user_ip(cmd)
        else:
            return None

    async def _handle_user_ip(self, cmd: UserIpCommand):
        await self._store.insert_client_ip(
            cmd.user_id,
            cmd.access_token,
            cmd.ip,
            cmd.user_agent,
            cmd.device_id,
            cmd.last_seen,
        )

        assert self._server_notices_sender is not None
        await self._server_notices_sender.on_user_ip(cmd.user_id)

    def on_RDATA(self, conn: IReplicationConnection, cmd: RdataCommand):
        if cmd.instance_name == self._instance_name:
            # Ignore RDATA that are just our own echoes
            return

        stream_name = cmd.stream_name
        inbound_rdata_count.labels(stream_name).inc()

        # We put the received command into a queue here for two reasons:
        #   1. so we don't try and concurrently handle multiple rows for the
        #      same stream, and
        #   2. so we don't race with getting a POSITION command and fetching
        #      missing RDATA.

        self._add_command_to_stream_queue(conn, cmd)

    async def _process_rdata(
        self, stream_name: str, conn: IReplicationConnection, cmd: RdataCommand
    ) -> None:
        """Process an RDATA command

        Called after the command has been popped off the queue of inbound commands
        """
        try:
            row = STREAMS_MAP[stream_name].parse_row(cmd.row)
        except Exception as e:
            raise Exception(
                "Failed to parse RDATA: %r %r" % (stream_name, cmd.row)
            ) from e

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
            return

        # Check if this is the last of a batch of updates
        rows = self._pending_batches.pop(stream_name, [])
        rows.append(row)

        stream = self._streams[stream_name]

        # Find where we previously streamed up to.
        current_token = stream.current_token(cmd.instance_name)

        # Discard this data if this token is earlier than the current
        # position. Note that streams can be reset (in which case you
        # expect an earlier token), but that must be preceded by a
        # POSITION command.
        if cmd.token <= current_token:
            logger.debug(
                "Discarding RDATA from stream %s at position %s before previous position %s",
                stream_name,
                cmd.token,
                current_token,
            )
        else:
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

    def on_POSITION(self, conn: IReplicationConnection, cmd: PositionCommand):
        if cmd.instance_name == self._instance_name:
            # Ignore POSITION that are just our own echoes
            return

        logger.info("Handling '%s %s'", cmd.NAME, cmd.to_line())

        self._add_command_to_stream_queue(conn, cmd)

    async def _process_position(
        self, stream_name: str, conn: IReplicationConnection, cmd: PositionCommand
    ) -> None:
        """Process a POSITION command

        Called after the command has been popped off the queue of inbound commands
        """
        stream = self._streams[stream_name]

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
        missing_updates = cmd.prev_token != current_token
        while missing_updates:
            logger.info(
                "Fetching replication rows for '%s' between %i and %i",
                stream_name,
                current_token,
                cmd.new_token,
            )
            (updates, current_token, missing_updates) = await stream.get_updates_since(
                cmd.instance_name, current_token, cmd.new_token
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

        logger.info("Caught up with stream '%s' to %i", stream_name, cmd.new_token)

        # We've now caught up to position sent to us, notify handler.
        await self._replication_data_handler.on_position(
            cmd.stream_name, cmd.instance_name, cmd.new_token
        )

        self._streams_by_connection.setdefault(conn, set()).add(stream_name)

    def on_REMOTE_SERVER_UP(
        self, conn: IReplicationConnection, cmd: RemoteServerUpCommand
    ):
        """Called when get a new REMOTE_SERVER_UP command."""
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

    def new_connection(self, connection: IReplicationConnection):
        """Called when we have a new connection."""
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

    def lost_connection(self, connection: IReplicationConnection):
        """Called when a connection is closed/lost."""
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
        self, cmd: Command, ignore_conn: Optional[IReplicationConnection] = None
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
        self.send_command(FederationAckCommand(self._instance_name, token))

    def send_user_sync(
        self, instance_id: str, user_id: str, is_syncing: bool, last_sync_ms: int
    ):
        """Poke the master that a user has started/stopped syncing."""
        self.send_command(
            UserSyncCommand(instance_id, user_id, is_syncing, last_sync_ms)
        )

    def send_user_ip(
        self,
        user_id: str,
        access_token: str,
        ip: str,
        user_agent: str,
        device_id: str,
        last_seen: int,
    ):
        """Tell the master that the user made a request."""
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
