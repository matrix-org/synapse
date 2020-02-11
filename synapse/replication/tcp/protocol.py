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
"""This module contains the implementation of both the client and server
protocols.

The basic structure of the protocol is line based, where the initial word of
each line specifies the command. The rest of the line is parsed based on the
command. For example, the `RDATA` command is defined as::

    RDATA <stream_name> <token> <row_json>

(Note that `<row_json>` may contains spaces, but cannot contain newlines.)

Blank lines are ignored.

# Example

An example iteraction is shown below. Each line is prefixed with '>' or '<' to
indicate which side is sending, these are *not* included on the wire::

    * connection established *
    > SERVER localhost:8823
    > PING 1490197665618
    < NAME synapse.app.appservice
    < PING 1490197665618
    < REPLICATE events 1
    < REPLICATE backfill 1
    < REPLICATE caches 1
    > POSITION events 1
    > POSITION backfill 1
    > POSITION caches 1
    > RDATA caches 2 ["get_user_by_id",["@01register-user:localhost:8823"],1490197670513]
    > RDATA events 14 ["ev", ["$149019767112vOHxz:localhost:8823",
        "!AFDCvgApUmpdfVjIXm:localhost:8823","m.room.guest_access","",null]]
    < PING 1490197675618
    > ERROR server stopping
    * connection closed by server *
"""

import fcntl
import logging
import struct
from collections import defaultdict

from six import iteritems, iterkeys

from prometheus_client import Counter

from twisted.internet import defer
from twisted.protocols.basic import LineOnlyReceiver
from twisted.python.failure import Failure

from synapse.metrics import LaterGauge
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.util.logcontext import make_deferred_yieldable, run_in_background
from synapse.util.stringutils import random_string

from .commands import (
    COMMAND_MAP,
    VALID_CLIENT_COMMANDS,
    VALID_SERVER_COMMANDS,
    ErrorCommand,
    NameCommand,
    PingCommand,
    PositionCommand,
    RdataCommand,
    ReplicateCommand,
    ServerCommand,
    SyncCommand,
    UserSyncCommand,
)
from .streams import STREAMS_MAP

connection_close_counter = Counter(
    "synapse_replication_tcp_protocol_close_reason", "", ["reason_type"]
)

# A list of all connected protocols. This allows us to send metrics about the
# connections.
connected_connections = []


logger = logging.getLogger(__name__)


PING_TIME = 5000
PING_TIMEOUT_MULTIPLIER = 5
PING_TIMEOUT_MS = PING_TIME * PING_TIMEOUT_MULTIPLIER


class ConnectionStates(object):
    CONNECTING = "connecting"
    ESTABLISHED = "established"
    PAUSED = "paused"
    CLOSED = "closed"


class BaseReplicationStreamProtocol(LineOnlyReceiver):
    """Base replication protocol shared between client and server.

    Reads lines (ignoring blank ones) and parses them into command classes,
    asserting that they are valid for the given direction, i.e. server commands
    are only sent by the server.

    On receiving a new command it calls `on_<COMMAND_NAME>` with the parsed
    command.

    It also sends `PING` periodically, and correctly times out remote connections
    (if they send a `PING` command)
    """

    delimiter = b"\n"

    VALID_INBOUND_COMMANDS = []  # Valid commands we expect to receive
    VALID_OUTBOUND_COMMANDS = []  # Valid commans we can send

    max_line_buffer = 10000

    def __init__(self, clock):
        self.clock = clock

        self.last_received_command = self.clock.time_msec()
        self.last_sent_command = 0
        self.time_we_closed = None  # When we requested the connection be closed

        self.received_ping = False  # Have we reecived a ping from the other side

        self.state = ConnectionStates.CONNECTING

        self.name = "anon"  # The name sent by a client.
        self.conn_id = random_string(5)  # To dedupe in case of name clashes.

        # List of pending commands to send once we've established the connection
        self.pending_commands = []

        # The LoopingCall for sending pings.
        self._send_ping_loop = None

        self.inbound_commands_counter = defaultdict(int)
        self.outbound_commands_counter = defaultdict(int)

    def connectionMade(self):
        logger.info("[%s] Connection established", self.id())

        self.state = ConnectionStates.ESTABLISHED

        connected_connections.append(self)  # Register connection for metrics

        self.transport.registerProducer(self, True)  # For the *Producing callbacks

        self._send_pending_commands()

        # Starts sending pings
        self._send_ping_loop = self.clock.looping_call(self.send_ping, 5000)

        # Always send the initial PING so that the other side knows that they
        # can time us out.
        self.send_command(PingCommand(self.clock.time_msec()))

    def send_ping(self):
        """Periodically sends a ping and checks if we should close the connection
        due to the other side timing out.
        """
        now = self.clock.time_msec()

        if self.time_we_closed:
            if now - self.time_we_closed > PING_TIMEOUT_MS:
                logger.info(
                    "[%s] Failed to close connection gracefully, aborting", self.id()
                )
                self.transport.abortConnection()
        else:
            if now - self.last_sent_command >= PING_TIME:
                self.send_command(PingCommand(now))

            if (
                self.received_ping
                and now - self.last_received_command > PING_TIMEOUT_MS
            ):
                logger.info(
                    "[%s] Connection hasn't received command in %r ms. Closing.",
                    self.id(),
                    now - self.last_received_command,
                )
                self.send_error("ping timeout")

    def lineReceived(self, line):
        """Called when we've received a line
        """
        if line.strip() == "":
            # Ignore blank lines
            return

        line = line.decode("utf-8")
        cmd_name, rest_of_line = line.split(" ", 1)

        if cmd_name not in self.VALID_INBOUND_COMMANDS:
            logger.error("[%s] invalid command %s", self.id(), cmd_name)
            self.send_error("invalid command: %s", cmd_name)
            return

        self.last_received_command = self.clock.time_msec()

        self.inbound_commands_counter[cmd_name] = (
            self.inbound_commands_counter[cmd_name] + 1
        )

        cmd_cls = COMMAND_MAP[cmd_name]
        try:
            cmd = cmd_cls.from_line(rest_of_line)
        except Exception as e:
            logger.exception(
                "[%s] failed to parse line %r: %r", self.id(), cmd_name, rest_of_line
            )
            self.send_error(
                "failed to parse line for  %r: %r (%r):" % (cmd_name, e, rest_of_line)
            )
            return

        # Now lets try and call on_<CMD_NAME> function
        run_as_background_process(
            "replication-" + cmd.get_logcontext_id(), self.handle_command, cmd
        )

    def handle_command(self, cmd):
        """Handle a command we have received over the replication stream.

        By default delegates to on_<COMMAND>

        Args:
            cmd (synapse.replication.tcp.commands.Command): received command

        Returns:
            Deferred
        """
        handler = getattr(self, "on_%s" % (cmd.NAME,))
        return handler(cmd)

    def close(self):
        logger.warn("[%s] Closing connection", self.id())
        self.time_we_closed = self.clock.time_msec()
        self.transport.loseConnection()
        self.on_connection_closed()

    def send_error(self, error_string, *args):
        """Send an error to remote and close the connection.
        """
        self.send_command(ErrorCommand(error_string % args))
        self.close()

    def send_command(self, cmd, do_buffer=True):
        """Send a command if connection has been established.

        Args:
            cmd (Command)
            do_buffer (bool): Whether to buffer the message or always attempt
                to send the command. This is mostly used to send an error
                message if we're about to close the connection due our buffers
                becoming full.
        """
        if self.state == ConnectionStates.CLOSED:
            logger.debug("[%s] Not sending, connection closed", self.id())
            return

        if do_buffer and self.state != ConnectionStates.ESTABLISHED:
            self._queue_command(cmd)
            return

        self.outbound_commands_counter[cmd.NAME] = (
            self.outbound_commands_counter[cmd.NAME] + 1
        )
        string = "%s %s" % (cmd.NAME, cmd.to_line())
        if "\n" in string:
            raise Exception("Unexpected newline in command: %r", string)

        encoded_string = string.encode("utf-8")

        if len(encoded_string) > self.MAX_LENGTH:
            raise Exception(
                "Failed to send command %s as too long (%d > %d)"
                % (cmd.NAME, len(encoded_string), self.MAX_LENGTH)
            )

        self.sendLine(encoded_string)

        self.last_sent_command = self.clock.time_msec()

    def _queue_command(self, cmd):
        """Queue the command until the connection is ready to write to again.
        """
        logger.debug("[%s] Queing as conn %r, cmd: %r", self.id(), self.state, cmd)
        self.pending_commands.append(cmd)

        if len(self.pending_commands) > self.max_line_buffer:
            # The other side is failing to keep up and out buffers are becoming
            # full, so lets close the connection.
            # XXX: should we squawk more loudly?
            logger.error("[%s] Remote failed to keep up", self.id())
            self.send_command(ErrorCommand("Failed to keep up"), do_buffer=False)
            self.close()

    def _send_pending_commands(self):
        """Send any queued commandes
        """
        pending = self.pending_commands
        self.pending_commands = []
        for cmd in pending:
            self.send_command(cmd)

    def on_PING(self, line):
        self.received_ping = True

    def on_ERROR(self, cmd):
        logger.error("[%s] Remote reported error: %r", self.id(), cmd.data)

    def pauseProducing(self):
        """This is called when both the kernel send buffer and the twisted
        tcp connection send buffers have become full.

        We don't actually have any control over those sizes, so we buffer some
        commands ourselves before knifing the connection due to the remote
        failing to keep up.
        """
        logger.info("[%s] Pause producing", self.id())
        self.state = ConnectionStates.PAUSED

    def resumeProducing(self):
        """The remote has caught up after we started buffering!
        """
        logger.info("[%s] Resume producing", self.id())
        self.state = ConnectionStates.ESTABLISHED
        self._send_pending_commands()

    def stopProducing(self):
        """We're never going to send any more data (normally because either
        we or the remote has closed the connection)
        """
        logger.info("[%s] Stop producing", self.id())
        self.on_connection_closed()

    def connectionLost(self, reason):
        logger.info("[%s] Replication connection closed: %r", self.id(), reason)
        if isinstance(reason, Failure):
            connection_close_counter.labels(reason.type.__name__).inc()
        else:
            connection_close_counter.labels(reason.__class__.__name__).inc()

        try:
            # Remove us from list of connections to be monitored
            connected_connections.remove(self)
        except ValueError:
            pass

        # Stop the looping call sending pings.
        if self._send_ping_loop and self._send_ping_loop.running:
            self._send_ping_loop.stop()

        self.on_connection_closed()

    def on_connection_closed(self):
        logger.info("[%s] Connection was closed", self.id())

        self.state = ConnectionStates.CLOSED
        self.pending_commands = []

        if self.transport:
            self.transport.unregisterProducer()

    def __str__(self):
        addr = None
        if self.transport:
            addr = str(self.transport.getPeer())
        return "ReplicationConnection<name=%s,conn_id=%s,addr=%s>" % (
            self.name,
            self.conn_id,
            addr,
        )

    def id(self):
        return "%s-%s" % (self.name, self.conn_id)

    def lineLengthExceeded(self, line):
        """Called when we receive a line that is above the maximum line length
        """
        self.send_error("Line length exceeded")


class ServerReplicationStreamProtocol(BaseReplicationStreamProtocol):
    VALID_INBOUND_COMMANDS = VALID_CLIENT_COMMANDS
    VALID_OUTBOUND_COMMANDS = VALID_SERVER_COMMANDS

    def __init__(self, server_name, clock, streamer):
        BaseReplicationStreamProtocol.__init__(self, clock)  # Old style class

        self.server_name = server_name
        self.streamer = streamer

        # The streams the client has subscribed to and is up to date with
        self.replication_streams = set()

        # The streams the client is currently subscribing to.
        self.connecting_streams = set()

        # Map from stream name to list of updates to send once we've finished
        # subscribing the client to the stream.
        self.pending_rdata = {}

    def connectionMade(self):
        self.send_command(ServerCommand(self.server_name))
        BaseReplicationStreamProtocol.connectionMade(self)
        self.streamer.new_connection(self)

    def on_NAME(self, cmd):
        logger.info("[%s] Renamed to %r", self.id(), cmd.data)
        self.name = cmd.data

    def on_USER_SYNC(self, cmd):
        return self.streamer.on_user_sync(
            self.conn_id, cmd.user_id, cmd.is_syncing, cmd.last_sync_ms
        )

    def on_REPLICATE(self, cmd):
        stream_name = cmd.stream_name
        token = cmd.token

        if stream_name == "ALL":
            # Subscribe to all streams we're publishing to.
            deferreds = [
                run_in_background(self.subscribe_to_stream, stream, token)
                for stream in iterkeys(self.streamer.streams_by_name)
            ]

            return make_deferred_yieldable(
                defer.gatherResults(deferreds, consumeErrors=True)
            )
        else:
            return self.subscribe_to_stream(stream_name, token)

    def on_FEDERATION_ACK(self, cmd):
        return self.streamer.federation_ack(cmd.token)

    def on_REMOVE_PUSHER(self, cmd):
        return self.streamer.on_remove_pusher(cmd.app_id, cmd.push_key, cmd.user_id)

    def on_INVALIDATE_CACHE(self, cmd):
        return self.streamer.on_invalidate_cache(cmd.cache_func, cmd.keys)

    def on_USER_IP(self, cmd):
        return self.streamer.on_user_ip(
            cmd.user_id,
            cmd.access_token,
            cmd.ip,
            cmd.user_agent,
            cmd.device_id,
            cmd.last_seen,
        )

    @defer.inlineCallbacks
    def subscribe_to_stream(self, stream_name, token):
        """Subscribe the remote to a stream.

        This invloves checking if they've missed anything and sending those
        updates down if they have. During that time new updates for the stream
        are queued and sent once we've sent down any missed updates.
        """
        self.replication_streams.discard(stream_name)
        self.connecting_streams.add(stream_name)

        try:
            # Get missing updates
            updates, current_token = yield self.streamer.get_stream_updates(
                stream_name, token
            )

            # Send all the missing updates
            for update in updates:
                token, row = update[0], update[1]
                self.send_command(RdataCommand(stream_name, token, row))

            # We send a POSITION command to ensure that they have an up to
            # date token (especially useful if we didn't send any updates
            # above)
            self.send_command(PositionCommand(stream_name, current_token))

            # Now we can send any updates that came in while we were subscribing
            pending_rdata = self.pending_rdata.pop(stream_name, [])
            updates = []
            for token, update in pending_rdata:
                # If the token is null, it is part of a batch update. Batches
                # are multiple updates that share a single token. To denote
                # this, the token is set to None for all tokens in the batch
                # except for the last. If we find a None token, we keep looking
                # through tokens until we find one that is not None and then
                # process all previous updates in the batch as if they had the
                # final token.
                if token is None:
                    # Store this update as part of a batch
                    updates.append(update)
                    continue

                if token <= current_token:
                    # This update or batch of updates is older than
                    # current_token, dismiss it
                    updates = []
                    continue

                updates.append(update)

                # Send all updates that are part of this batch with the
                # found token
                for update in updates:
                    self.send_command(RdataCommand(stream_name, token, update))

                # Clear stored updates
                updates = []

            # They're now fully subscribed
            self.replication_streams.add(stream_name)
        except Exception as e:
            logger.exception("[%s] Failed to handle REPLICATE command", self.id())
            self.send_error("failed to handle replicate: %r", e)
        finally:
            self.connecting_streams.discard(stream_name)

    def stream_update(self, stream_name, token, data):
        """Called when a new update is available to stream to clients.

        We need to check if the client is interested in the stream or not
        """
        if stream_name in self.replication_streams:
            # The client is subscribed to the stream
            self.send_command(RdataCommand(stream_name, token, data))
        elif stream_name in self.connecting_streams:
            # The client is being subscribed to the stream
            logger.debug("[%s] Queuing RDATA %r %r", self.id(), stream_name, token)
            self.pending_rdata.setdefault(stream_name, []).append((token, data))
        else:
            # The client isn't subscribed
            logger.debug("[%s] Dropping RDATA %r %r", self.id(), stream_name, token)

    def send_sync(self, data):
        self.send_command(SyncCommand(data))

    def on_connection_closed(self):
        BaseReplicationStreamProtocol.on_connection_closed(self)
        self.streamer.lost_connection(self)


class ClientReplicationStreamProtocol(BaseReplicationStreamProtocol):
    VALID_INBOUND_COMMANDS = VALID_SERVER_COMMANDS
    VALID_OUTBOUND_COMMANDS = VALID_CLIENT_COMMANDS

    def __init__(self, client_name, server_name, clock, handler):
        BaseReplicationStreamProtocol.__init__(self, clock)

        self.client_name = client_name
        self.server_name = server_name
        self.handler = handler

        # Set of stream names that have been subscribe to, but haven't yet
        # caught up with. This is used to track when the client has been fully
        # connected to the remote.
        self.streams_connecting = set()

        # Map of stream to batched updates. See RdataCommand for info on how
        # batching works.
        self.pending_batches = {}

    def connectionMade(self):
        self.send_command(NameCommand(self.client_name))
        BaseReplicationStreamProtocol.connectionMade(self)

        # Once we've connected subscribe to the necessary streams
        for stream_name, token in iteritems(self.handler.get_streams_to_replicate()):
            self.replicate(stream_name, token)

        # Tell the server if we have any users currently syncing (should only
        # happen on synchrotrons)
        currently_syncing = self.handler.get_currently_syncing_users()
        now = self.clock.time_msec()
        for user_id in currently_syncing:
            self.send_command(UserSyncCommand(user_id, True, now))

        # We've now finished connecting to so inform the client handler
        self.handler.update_connection(self)

        # This will happen if we don't actually subscribe to any streams
        if not self.streams_connecting:
            self.handler.finished_connecting()

    def on_SERVER(self, cmd):
        if cmd.data != self.server_name:
            logger.error("[%s] Connected to wrong remote: %r", self.id(), cmd.data)
            self.send_error("Wrong remote")

    def on_RDATA(self, cmd):
        stream_name = cmd.stream_name
        inbound_rdata_count.labels(stream_name).inc()

        try:
            row = STREAMS_MAP[stream_name].parse_row(cmd.row)
        except Exception:
            logger.exception(
                "[%s] Failed to parse RDATA: %r %r", self.id(), stream_name, cmd.row
            )
            raise

        if cmd.token is None:
            # I.e. this is part of a batch of updates for this stream. Batch
            # until we get an update for the stream with a non None token
            self.pending_batches.setdefault(stream_name, []).append(row)
        else:
            # Check if this is the last of a batch of updates
            rows = self.pending_batches.pop(stream_name, [])
            rows.append(row)
            return self.handler.on_rdata(stream_name, cmd.token, rows)

    def on_POSITION(self, cmd):
        # When we get a `POSITION` command it means we've finished getting
        # missing updates for the given stream, and are now up to date.
        self.streams_connecting.discard(cmd.stream_name)
        if not self.streams_connecting:
            self.handler.finished_connecting()

        return self.handler.on_position(cmd.stream_name, cmd.token)

    def on_SYNC(self, cmd):
        return self.handler.on_sync(cmd.data)

    def replicate(self, stream_name, token):
        """Send the subscription request to the server
        """
        if stream_name not in STREAMS_MAP:
            raise Exception("Invalid stream name %r" % (stream_name,))

        logger.info(
            "[%s] Subscribing to replication stream: %r from %r",
            self.id(),
            stream_name,
            token,
        )

        self.streams_connecting.add(stream_name)

        self.send_command(ReplicateCommand(stream_name, token))

    def on_connection_closed(self):
        BaseReplicationStreamProtocol.on_connection_closed(self)
        self.handler.update_connection(None)


# The following simply registers metrics for the replication connections

pending_commands = LaterGauge(
    "synapse_replication_tcp_protocol_pending_commands",
    "",
    ["name"],
    lambda: {(p.name,): len(p.pending_commands) for p in connected_connections},
)


def transport_buffer_size(protocol):
    if protocol.transport:
        size = len(protocol.transport.dataBuffer) + protocol.transport._tempDataLen
        return size
    return 0


transport_send_buffer = LaterGauge(
    "synapse_replication_tcp_protocol_transport_send_buffer",
    "",
    ["name"],
    lambda: {(p.name,): transport_buffer_size(p) for p in connected_connections},
)


def transport_kernel_read_buffer_size(protocol, read=True):
    SIOCINQ = 0x541B
    SIOCOUTQ = 0x5411

    if protocol.transport:
        fileno = protocol.transport.getHandle().fileno()
        if read:
            op = SIOCINQ
        else:
            op = SIOCOUTQ
        size = struct.unpack("I", fcntl.ioctl(fileno, op, "\0\0\0\0"))[0]
        return size
    return 0


tcp_transport_kernel_send_buffer = LaterGauge(
    "synapse_replication_tcp_protocol_transport_kernel_send_buffer",
    "",
    ["name"],
    lambda: {
        (p.name,): transport_kernel_read_buffer_size(p, False)
        for p in connected_connections
    },
)


tcp_transport_kernel_read_buffer = LaterGauge(
    "synapse_replication_tcp_protocol_transport_kernel_read_buffer",
    "",
    ["name"],
    lambda: {
        (p.name,): transport_kernel_read_buffer_size(p, True)
        for p in connected_connections
    },
)


tcp_inbound_commands = LaterGauge(
    "synapse_replication_tcp_protocol_inbound_commands",
    "",
    ["command", "name"],
    lambda: {
        (k, p.name): count
        for p in connected_connections
        for k, count in iteritems(p.inbound_commands_counter)
    },
)

tcp_outbound_commands = LaterGauge(
    "synapse_replication_tcp_protocol_outbound_commands",
    "",
    ["command", "name"],
    lambda: {
        (k, p.name): count
        for p in connected_connections
        for k, count in iteritems(p.outbound_commands_counter)
    },
)

# number of updates received for each RDATA stream
inbound_rdata_count = Counter(
    "synapse_replication_tcp_protocol_inbound_rdata_count", "", ["stream_name"]
)
