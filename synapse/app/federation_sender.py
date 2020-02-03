#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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
import sys

from twisted.internet import defer, reactor
from twisted.web.resource import NoResource

import synapse
from synapse import events
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.federation import send_queue
from synapse.http.site import SynapseSite
from synapse.logging.context import LoggingContext, run_in_background
from synapse.metrics import METRICS_PREFIX, MetricsResource, RegistryProxy
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.slave.storage.deviceinbox import SlavedDeviceInboxStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.presence import SlavedPresenceStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.transactions import SlavedTransactionStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.replication.tcp.streams._base import (
    DeviceListsStream,
    ReceiptsStream,
    ToDeviceStream,
)
from synapse.server import HomeServer
from synapse.storage.database import Database
from synapse.types import ReadReceipt
from synapse.util.async_helpers import Linearizer
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.federation_sender")


class FederationSenderSlaveStore(
    SlavedDeviceInboxStore,
    SlavedTransactionStore,
    SlavedReceiptsStore,
    SlavedEventStore,
    SlavedRegistrationStore,
    SlavedDeviceStore,
    SlavedPresenceStore,
):
    def __init__(self, database: Database, db_conn, hs):
        super(FederationSenderSlaveStore, self).__init__(database, db_conn, hs)

        # We pull out the current federation stream position now so that we
        # always have a known value for the federation position in memory so
        # that we don't have to bounce via a deferred once when we start the
        # replication streams.
        self.federation_out_pos_startup = self._get_federation_out_pos(db_conn)

    def _get_federation_out_pos(self, db_conn):
        sql = "SELECT stream_id FROM federation_stream_position WHERE type = ?"
        sql = self.database_engine.convert_param_style(sql)

        txn = db_conn.cursor()
        txn.execute(sql, ("federation",))
        rows = txn.fetchall()
        txn.close()

        return rows[0][0] if rows else -1


class FederationSenderServer(HomeServer):
    DATASTORE_CLASS = FederationSenderSlaveStore

    def _listen_http(self, listener_config):
        port = listener_config["port"]
        bind_addresses = listener_config["bind_addresses"]
        site_tag = listener_config.get("tag", port)
        resources = {}
        for res in listener_config["resources"]:
            for name in res["names"]:
                if name == "metrics":
                    resources[METRICS_PREFIX] = MetricsResource(RegistryProxy)

        root_resource = create_resource_tree(resources, NoResource())

        _base.listen_tcp(
            bind_addresses,
            port,
            SynapseSite(
                "synapse.access.http.%s" % (site_tag,),
                site_tag,
                listener_config,
                root_resource,
                self.version_string,
            ),
        )

        logger.info("Synapse federation_sender now listening on port %d", port)

    def start_listening(self, listeners):
        for listener in listeners:
            if listener["type"] == "http":
                self._listen_http(listener)
            elif listener["type"] == "manhole":
                _base.listen_tcp(
                    listener["bind_addresses"],
                    listener["port"],
                    manhole(
                        username="matrix", password="rabbithole", globals={"hs": self}
                    ),
                )
            elif listener["type"] == "metrics":
                if not self.get_config().enable_metrics:
                    logger.warning(
                        (
                            "Metrics listener configured, but "
                            "enable_metrics is not True!"
                        )
                    )
                else:
                    _base.listen_metrics(listener["bind_addresses"], listener["port"])
            else:
                logger.warning("Unrecognized listener type: %s", listener["type"])

        self.get_tcp_replication().start_replication(self)

    def build_tcp_replication(self):
        return FederationSenderReplicationHandler(self)


class FederationSenderReplicationHandler(ReplicationClientHandler):
    def __init__(self, hs):
        super(FederationSenderReplicationHandler, self).__init__(hs.get_datastore())
        self.send_handler = FederationSenderHandler(hs, self)

    async def on_rdata(self, stream_name, token, rows):
        await super(FederationSenderReplicationHandler, self).on_rdata(
            stream_name, token, rows
        )
        self.send_handler.process_replication_rows(stream_name, token, rows)

    def get_streams_to_replicate(self):
        args = super(
            FederationSenderReplicationHandler, self
        ).get_streams_to_replicate()
        args.update(self.send_handler.stream_positions())
        return args

    def on_remote_server_up(self, server: str):
        """Called when get a new REMOTE_SERVER_UP command."""

        # Let's wake up the transaction queue for the server in case we have
        # pending stuff to send to it.
        self.send_handler.wake_destination(server)


def start(config_options):
    try:
        config = HomeServerConfig.load_config(
            "Synapse federation sender", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.federation_sender"

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    if config.send_federation:
        sys.stderr.write(
            "\nThe send_federation must be disabled in the main synapse process"
            "\nbefore they can be run in a separate worker."
            "\nPlease add ``send_federation: false`` to the main config"
            "\n"
        )
        sys.exit(1)

    # Force the pushers to start since they will be disabled in the main config
    config.send_federation = True

    ss = FederationSenderServer(
        config.server_name,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
    )

    setup_logging(ss, config, use_worker_options=True)

    ss.setup()
    reactor.addSystemEventTrigger(
        "before", "startup", _base.start, ss, config.worker_listeners
    )

    _base.start_worker_reactor("synapse-federation-sender", config)


class FederationSenderHandler(object):
    """Processes the replication stream and forwards the appropriate entries
    to the federation sender.
    """

    def __init__(self, hs: FederationSenderServer, replication_client):
        self.store = hs.get_datastore()
        self._is_mine_id = hs.is_mine_id
        self.federation_sender = hs.get_federation_sender()
        self.replication_client = replication_client

        self.federation_position = self.store.federation_out_pos_startup
        self._fed_position_linearizer = Linearizer(name="_fed_position_linearizer")

        self._last_ack = self.federation_position

        self._room_serials = {}
        self._room_typing = {}

    def on_start(self):
        # There may be some events that are persisted but haven't been sent,
        # so send them now.
        self.federation_sender.notify_new_events(
            self.store.get_room_max_stream_ordering()
        )

    def wake_destination(self, server: str):
        self.federation_sender.wake_destination(server)

    def stream_positions(self):
        return {"federation": self.federation_position}

    def process_replication_rows(self, stream_name, token, rows):
        # The federation stream contains things that we want to send out, e.g.
        # presence, typing, etc.
        if stream_name == "federation":
            send_queue.process_rows_for_federation(self.federation_sender, rows)
            run_in_background(self.update_token, token)

        # We also need to poke the federation sender when new events happen
        elif stream_name == "events":
            self.federation_sender.notify_new_events(token)

        # ... and when new receipts happen
        elif stream_name == ReceiptsStream.NAME:
            run_as_background_process(
                "process_receipts_for_federation", self._on_new_receipts, rows
            )

        # ... as well as device updates and messages
        elif stream_name == DeviceListsStream.NAME:
            hosts = set(row.destination for row in rows)
            for host in hosts:
                self.federation_sender.send_device_messages(host)

        elif stream_name == ToDeviceStream.NAME:
            # The to_device stream includes stuff to be pushed to both local
            # clients and remote servers, so we ignore entities that start with
            # '@' (since they'll be local users rather than destinations).
            hosts = set(row.entity for row in rows if not row.entity.startswith("@"))
            for host in hosts:
                self.federation_sender.send_device_messages(host)

    @defer.inlineCallbacks
    def _on_new_receipts(self, rows):
        """
        Args:
            rows (iterable[synapse.replication.tcp.streams.ReceiptsStreamRow]):
                new receipts to be processed
        """
        for receipt in rows:
            # we only want to send on receipts for our own users
            if not self._is_mine_id(receipt.user_id):
                continue
            receipt_info = ReadReceipt(
                receipt.room_id,
                receipt.receipt_type,
                receipt.user_id,
                [receipt.event_id],
                receipt.data,
            )
            yield self.federation_sender.send_read_receipt(receipt_info)

    @defer.inlineCallbacks
    def update_token(self, token):
        try:
            self.federation_position = token

            # We linearize here to ensure we don't have races updating the token
            with (yield self._fed_position_linearizer.queue(None)):
                if self._last_ack < self.federation_position:
                    yield self.store.update_federation_out_pos(
                        "federation", self.federation_position
                    )

                    # We ACK this token over replication so that the master can drop
                    # its in memory queues
                    self.replication_client.send_federation_ack(
                        self.federation_position
                    )
                    self._last_ack = self.federation_position
        except Exception:
            logger.exception("Error updating federation stream position")


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
