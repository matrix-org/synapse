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

from twisted.internet import defer, reactor
from twisted.internet.protocol import Factory

from streams import STREAMS_MAP, FederationStream
from protocol import ServerReplicationStreamProtocol

from synapse.util.metrics import Measure, measure_func

import logging
import synapse.metrics


metrics = synapse.metrics.get_metrics_for(__name__)
stream_updates_counter = metrics.register_counter(
    "stream_updates", labels=["stream_name"]
)
user_sync_counter = metrics.register_counter("user_sync")
federation_ack_counter = metrics.register_counter("federation_ack")
remove_pusher_counter = metrics.register_counter("remove_pusher")
invalidate_cache_counter = metrics.register_counter("invalidate_cache")
user_ip_cache_counter = metrics.register_counter("user_ip_cache")

logger = logging.getLogger(__name__)


class ReplicationStreamProtocolFactory(Factory):
    """Factory for new replication connections.
    """
    def __init__(self, hs):
        self.streamer = ReplicationStreamer(hs)
        self.clock = hs.get_clock()
        self.server_name = hs.config.server_name

    def buildProtocol(self, addr):
        return ServerReplicationStreamProtocol(
            self.server_name,
            self.clock,
            self.streamer,
            addr
        )


class ReplicationStreamer(object):
    """Handles replication connections.

    This needs to be poked when new replication data may be available. When new
    data is available it will propagate to all connected clients.
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.presence_handler = hs.get_presence_handler()
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()

        # Current connections.
        self.connections = []

        metrics.register_callback("total_connections", lambda: len(self.connections))

        # List of streams that clients can subscribe to.
        # We only support federation stream if federation sending hase been
        # disabled on the master.
        self.streams = [
            stream(hs) for stream in STREAMS_MAP.itervalues()
            if stream != FederationStream or not hs.config.send_federation
        ]

        self.streams_by_name = {stream.NAME: stream for stream in self.streams}

        metrics.register_callback(
            "connections_per_stream",
            lambda: {
                (stream_name,): len([
                    conn for conn in self.connections
                    if stream_name in conn.replication_streams
                ])
                for stream_name in self.streams_by_name
            },
            labels=["stream_name"],
        )

        self.federation_sender = None
        if not hs.config.send_federation:
            self.federation_sender = hs.get_federation_sender()

        self.notifier.add_replication_callback(self.on_notifier_poke)

        # Keeps track of whether we are currently checking for updates
        self.is_looping = False
        self.pending_updates = False

        reactor.addSystemEventTrigger("before", "shutdown", self.on_shutdown)

    def on_shutdown(self):
        # close all connections on shutdown
        for conn in self.connections:
            conn.send_error("server shutting down")

    @defer.inlineCallbacks
    def on_notifier_poke(self):
        """Checks if there is actually any new data and sends it to the
        connections if there are.

        This should get called each time new data is available, even if it
        is currently being executed, so that nothing gets missed
        """
        if not self.connections:
            # Don't bother if nothing is listening. We still need to advance
            # the stream tokens otherwise they'll fall beihind forever
            for stream in self.streams:
                stream.discard_updates_and_advance()
            return

        # If we're in the process of checking for new updates, mark that fact
        # and return
        if self.is_looping:
            logger.debug("Noitifier poke loop already running")
            self.pending_updates = True
            return

        self.pending_updates = True
        self.is_looping = True

        try:
            # Keep looping while there have been pokes about potential updates.
            # This protects against the race where a stream we already checked
            # gets an update while we're handling other streams.
            while self.pending_updates:
                self.pending_updates = False

                with Measure(self.clock, "repl.stream.get_updates"):
                    # First we tell the streams that they should update their
                    # current tokens.
                    for stream in self.streams:
                        stream.advance_current_token()

                    for stream in self.streams:
                        if stream.last_token == stream.upto_token:
                            continue

                        logger.debug(
                            "Getting stream: %s: %s -> %s",
                            stream.NAME, stream.last_token, stream.upto_token
                        )
                        try:
                            updates, current_token = yield stream.get_updates()
                        except Exception:
                            logger.info("Failed to handle stream %s", stream.NAME)
                            raise

                        logger.debug(
                            "Sending %d updates to %d connections",
                            len(updates), len(self.connections),
                        )

                        if updates:
                            logger.info(
                                "Streaming: %s -> %s", stream.NAME, updates[-1][0]
                            )
                            stream_updates_counter.inc_by(len(updates), stream.NAME)

                        # Some streams return multiple rows with the same stream IDs,
                        # we need to make sure they get sent out in batches. We do
                        # this by setting the current token to all but the last of
                        # a series of updates with the same token to have a None
                        # token. See RdataCommand for more details.
                        batched_updates = _batch_updates(updates)

                        for conn in self.connections:
                            for token, row in batched_updates:
                                try:
                                    conn.stream_update(stream.NAME, token, row)
                                except Exception:
                                    logger.exception("Failed to replicate")

            logger.debug("No more pending updates, breaking poke loop")
        finally:
            self.pending_updates = False
            self.is_looping = False

    @measure_func("repl.get_stream_updates")
    def get_stream_updates(self, stream_name, token):
        """For a given stream get all updates since token. This is called when
        a client first subscribes to a stream.
        """
        stream = self.streams_by_name.get(stream_name, None)
        if not stream:
            raise Exception("unknown stream %s", stream_name)

        return stream.get_updates_since(token)

    @measure_func("repl.federation_ack")
    def federation_ack(self, token):
        """We've received an ack for federation stream from a client.
        """
        federation_ack_counter.inc()
        if self.federation_sender:
            self.federation_sender.federation_ack(token)

    @measure_func("repl.on_user_sync")
    def on_user_sync(self, conn_id, user_id, is_syncing, last_sync_ms):
        """A client has started/stopped syncing on a worker.
        """
        user_sync_counter.inc()
        self.presence_handler.update_external_syncs_row(
            conn_id, user_id, is_syncing, last_sync_ms,
        )

    @measure_func("repl.on_remove_pusher")
    @defer.inlineCallbacks
    def on_remove_pusher(self, app_id, push_key, user_id):
        """A client has asked us to remove a pusher
        """
        remove_pusher_counter.inc()
        yield self.store.delete_pusher_by_app_id_pushkey_user_id(
            app_id=app_id, pushkey=push_key, user_id=user_id
        )

        self.notifier.on_new_replication_data()

    @measure_func("repl.on_invalidate_cache")
    def on_invalidate_cache(self, cache_func, keys):
        """The client has asked us to invalidate a cache
        """
        invalidate_cache_counter.inc()
        getattr(self.store, cache_func).invalidate(tuple(keys))

    @measure_func("repl.on_user_ip")
    def on_user_ip(self, user_id, access_token, ip, user_agent, device_id, last_seen):
        """The client saw a user request
        """
        user_ip_cache_counter.inc()
        self.store.insert_client_ip(
            user_id, access_token, ip, user_agent, device_id, last_seen,
        )

    def send_sync_to_all_connections(self, data):
        """Sends a SYNC command to all clients.

        Used in tests.
        """
        for conn in self.connections:
            conn.send_sync(data)

    def new_connection(self, connection):
        """A new client connection has been established
        """
        self.connections.append(connection)

    def lost_connection(self, connection):
        """A client connection has been lost
        """
        try:
            self.connections.remove(connection)
        except ValueError:
            pass

        # We need to tell the presence handler that the connection has been
        # lost so that it can handle any ongoing syncs on that connection.
        self.presence_handler.update_external_syncs_clear(connection.conn_id)


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
