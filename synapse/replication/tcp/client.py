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

from twisted.internet import defer
from twisted.internet.protocol import ReconnectingClientFactory

from .commands import (
    FederationAckCommand,
    InvalidateCacheCommand,
    RemovePusherCommand,
    UserIpCommand,
    UserSyncCommand,
)
from .protocol import ClientReplicationStreamProtocol

logger = logging.getLogger(__name__)


class ReplicationClientFactory(ReconnectingClientFactory):
    """Factory for building connections to the master. Will reconnect if the
    connection is lost.

    Accepts a handler that will be called when new data is available or data
    is required.
    """
    maxDelay = 5  # Try at least once every N seconds

    def __init__(self, hs, client_name, handler):
        self.client_name = client_name
        self.handler = handler
        self.server_name = hs.config.server_name
        self._clock = hs.get_clock()  # As self.clock is defined in super class

        hs.get_reactor().addSystemEventTrigger("before", "shutdown", self.stopTrying)

    def startedConnecting(self, connector):
        logger.info("Connecting to replication: %r", connector.getDestination())

    def buildProtocol(self, addr):
        logger.info("Connected to replication: %r", addr)
        self.resetDelay()
        return ClientReplicationStreamProtocol(
            self.client_name, self.server_name, self._clock, self.handler
        )

    def clientConnectionLost(self, connector, reason):
        logger.error("Lost replication conn: %r", reason)
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        logger.error("Failed to connect to replication: %r", reason)
        ReconnectingClientFactory.clientConnectionFailed(
            self, connector, reason
        )


class ReplicationClientHandler(object):
    """A base handler that can be passed to the ReplicationClientFactory.

    By default proxies incoming replication data to the SlaveStore.
    """
    def __init__(self, store):
        self.store = store

        # The current connection. None if we are currently (re)connecting
        self.connection = None

        # Any pending commands to be sent once a new connection has been
        # established
        self.pending_commands = []

        # Map from string -> deferred, to wake up when receiveing a SYNC with
        # the given string.
        # Used for tests.
        self.awaiting_syncs = {}

    def start_replication(self, hs):
        """Helper method to start a replication connection to the remote server
        using TCP.
        """
        client_name = hs.config.worker_name
        factory = ReplicationClientFactory(hs, client_name, self)
        host = hs.config.worker_replication_host
        port = hs.config.worker_replication_port
        hs.get_reactor().connectTCP(host, port, factory)

    def on_rdata(self, stream_name, token, rows):
        """Called when we get new replication data. By default this just pokes
        the slave store.

        Can be overriden in subclasses to handle more.
        """
        logger.info("Received rdata %s -> %s", stream_name, token)
        return self.store.process_replication_rows(stream_name, token, rows)

    def on_position(self, stream_name, token):
        """Called when we get new position data. By default this just pokes
        the slave store.

        Can be overriden in subclasses to handle more.
        """
        return self.store.process_replication_rows(stream_name, token, [])

    def on_sync(self, data):
        """When we received a SYNC we wake up any deferreds that were waiting
        for the sync with the given data.

        Used by tests.
        """
        d = self.awaiting_syncs.pop(data, None)
        if d:
            d.callback(data)

    def get_streams_to_replicate(self):
        """Called when a new connection has been established and we need to
        subscribe to streams.

        Returns a dictionary of stream name to token.
        """
        args = self.store.stream_positions()
        user_account_data = args.pop("user_account_data", None)
        room_account_data = args.pop("room_account_data", None)
        if user_account_data:
            args["account_data"] = user_account_data
        elif room_account_data:
            args["account_data"] = room_account_data
        return args

    def get_currently_syncing_users(self):
        """Get the list of currently syncing users (if any). This is called
        when a connection has been established and we need to send the
        currently syncing users. (Overriden by the synchrotron's only)
        """
        return []

    def send_command(self, cmd):
        """Send a command to master (when we get establish a connection if we
        don't have one already.)
        """
        if self.connection:
            self.connection.send_command(cmd)
        else:
            logger.warn("Queuing command as not connected: %r", cmd.NAME)
            self.pending_commands.append(cmd)

    def send_federation_ack(self, token):
        """Ack data for the federation stream. This allows the master to drop
        data stored purely in memory.
        """
        self.send_command(FederationAckCommand(token))

    def send_user_sync(self, user_id, is_syncing, last_sync_ms):
        """Poke the master that a user has started/stopped syncing.
        """
        self.send_command(UserSyncCommand(user_id, is_syncing, last_sync_ms))

    def send_remove_pusher(self, app_id, push_key, user_id):
        """Poke the master to remove a pusher for a user
        """
        cmd = RemovePusherCommand(app_id, push_key, user_id)
        self.send_command(cmd)

    def send_invalidate_cache(self, cache_func, keys):
        """Poke the master to invalidate a cache.
        """
        cmd = InvalidateCacheCommand(cache_func.__name__, keys)
        self.send_command(cmd)

    def send_user_ip(self, user_id, access_token, ip, user_agent, device_id, last_seen):
        """Tell the master that the user made a request.
        """
        cmd = UserIpCommand(user_id, access_token, ip, user_agent, device_id, last_seen)
        self.send_command(cmd)

    def await_sync(self, data):
        """Returns a deferred that is resolved when we receive a SYNC command
        with given data.

        [Not currently] used by tests.
        """
        return self.awaiting_syncs.setdefault(data, defer.Deferred())

    def update_connection(self, connection):
        """Called when a connection has been established (or lost with None).
        """
        self.connection = connection
        if connection:
            for cmd in self.pending_commands:
                connection.send_command(cmd)
            self.pending_commands = []
