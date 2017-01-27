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

import synapse

from synapse.server import HomeServer
from synapse.config._base import ConfigError
from synapse.config.logger import setup_logging
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.http.site import SynapseSite
from synapse.federation import send_queue
from synapse.federation.units import Edu
from synapse.metrics.resource import MetricsResource, METRICS_PREFIX
from synapse.replication.slave.storage.deviceinbox import SlavedDeviceInboxStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.transactions import TransactionStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.storage.engines import create_engine
from synapse.storage.presence import UserPresenceState
from synapse.util.async import sleep
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext
from synapse.util.manhole import manhole
from synapse.util.rlimit import change_resource_limit
from synapse.util.versionstring import get_version_string

from synapse import events

from twisted.internet import reactor, defer
from twisted.web.resource import Resource

from daemonize import Daemonize

import sys
import logging
import gc
import ujson as json

logger = logging.getLogger("synapse.app.appservice")


class FederationSenderSlaveStore(
    SlavedDeviceInboxStore, TransactionStore, SlavedReceiptsStore, SlavedEventStore,
    SlavedRegistrationStore, SlavedDeviceStore,
):
    pass


class FederationSenderServer(HomeServer):
    def get_db_conn(self, run_new_connection=True):
        # Any param beginning with cp_ is a parameter for adbapi, and should
        # not be passed to the database engine.
        db_params = {
            k: v for k, v in self.db_config.get("args", {}).items()
            if not k.startswith("cp_")
        }
        db_conn = self.database_engine.module.connect(**db_params)

        if run_new_connection:
            self.database_engine.on_new_connection(db_conn)
        return db_conn

    def setup(self):
        logger.info("Setting up.")
        self.datastore = FederationSenderSlaveStore(self.get_db_conn(), self)
        logger.info("Finished setting up.")

    def _listen_http(self, listener_config):
        port = listener_config["port"]
        bind_addresses = listener_config["bind_addresses"]
        site_tag = listener_config.get("tag", port)
        resources = {}
        for res in listener_config["resources"]:
            for name in res["names"]:
                if name == "metrics":
                    resources[METRICS_PREFIX] = MetricsResource(self)

        root_resource = create_resource_tree(resources, Resource())

        for address in bind_addresses:
            reactor.listenTCP(
                port,
                SynapseSite(
                    "synapse.access.http.%s" % (site_tag,),
                    site_tag,
                    listener_config,
                    root_resource,
                ),
                interface=address
            )

        logger.info("Synapse federation_sender now listening on port %d", port)

    def start_listening(self, listeners):
        for listener in listeners:
            if listener["type"] == "http":
                self._listen_http(listener)
            elif listener["type"] == "manhole":
                bind_addresses = listener["bind_addresses"]

                for address in bind_addresses:
                    reactor.listenTCP(
                        listener["port"],
                        manhole(
                            username="matrix",
                            password="rabbithole",
                            globals={"hs": self},
                        ),
                        interface=address
                    )
            else:
                logger.warn("Unrecognized listener type: %s", listener["type"])

    @defer.inlineCallbacks
    def replicate(self):
        http_client = self.get_simple_http_client()
        store = self.get_datastore()
        replication_url = self.config.worker_replication_url
        send_handler = FederationSenderHandler(self)

        send_handler.on_start()

        while True:
            try:
                args = store.stream_positions()
                args.update((yield send_handler.stream_positions()))
                args["timeout"] = 30000
                result = yield http_client.get_json(replication_url, args=args)
                yield store.process_replication(result)
                yield send_handler.process_replication(result)
            except:
                logger.exception("Error replicating from %r", replication_url)
                yield sleep(30)


def start(config_options):
    try:
        config = HomeServerConfig.load_config(
            "Synapse federation sender", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + e.message + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.federation_sender"

    setup_logging(config.worker_log_config, config.worker_log_file)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    database_engine = create_engine(config.database_config)

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

    tls_server_context_factory = context_factory.ServerContextFactory(config)

    ps = FederationSenderServer(
        config.server_name,
        db_config=config.database_config,
        tls_server_context_factory=tls_server_context_factory,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
    )

    ps.setup()
    ps.start_listening(config.worker_listeners)

    def run():
        with LoggingContext("run"):
            logger.info("Running")
            change_resource_limit(config.soft_file_limit)
            if config.gc_thresholds:
                gc.set_threshold(*config.gc_thresholds)
            reactor.run()

    def start():
        ps.replicate()
        ps.get_datastore().start_profiling()
        ps.get_state_handler().start_caching()

    reactor.callWhenRunning(start)

    if config.worker_daemonize:
        daemon = Daemonize(
            app="synapse-federation-sender",
            pid=config.worker_pid_file,
            action=run,
            auto_close_fds=False,
            verbose=True,
            logger=logger,
        )
        daemon.start()
    else:
        run()


class FederationSenderHandler(object):
    """Processes the replication stream and forwards the appropriate entries
    to the federation sender.
    """
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.federation_sender = hs.get_federation_sender()

        self._room_serials = {}
        self._room_typing = {}

    def on_start(self):
        # There may be some events that are persisted but haven't been sent,
        # so send them now.
        self.federation_sender.notify_new_events(
            self.store.get_room_max_stream_ordering()
        )

    @defer.inlineCallbacks
    def stream_positions(self):
        stream_id = yield self.store.get_federation_out_pos("federation")
        defer.returnValue({
            "federation": stream_id,

            # Ack stuff we've "processed", this should only be called from
            # one process.
            "federation_ack": stream_id,
        })

    @defer.inlineCallbacks
    def process_replication(self, result):
        # The federation stream contains things that we want to send out, e.g.
        # presence, typing, etc.
        fed_stream = result.get("federation")
        if fed_stream:
            latest_id = int(fed_stream["position"])

            # The federation stream containis a bunch of different types of
            # rows that need to be handled differently. We parse the rows, put
            # them into the appropriate collection and then send them off.
            presence_to_send = {}
            keyed_edus = {}
            edus = {}
            failures = {}
            device_destinations = set()

            # Parse the rows in the stream
            for row in fed_stream["rows"]:
                position, typ, content_js = row
                content = json.loads(content_js)

                if typ == send_queue.PRESENCE_TYPE:
                    destination = content["destination"]
                    state = UserPresenceState.from_dict(content["state"])

                    presence_to_send.setdefault(destination, []).append(state)
                elif typ == send_queue.KEYED_EDU_TYPE:
                    key = content["key"]
                    edu = Edu(**content["edu"])

                    keyed_edus.setdefault(
                        edu.destination, {}
                    )[(edu.destination, tuple(key))] = edu
                elif typ == send_queue.EDU_TYPE:
                    edu = Edu(**content)

                    edus.setdefault(edu.destination, []).append(edu)
                elif typ == send_queue.FAILURE_TYPE:
                    destination = content["destination"]
                    failure = content["failure"]

                    failures.setdefault(destination, []).append(failure)
                elif typ == send_queue.DEVICE_MESSAGE_TYPE:
                    device_destinations.add(content["destination"])
                else:
                    raise Exception("Unrecognised federation type: %r", typ)

            # We've finished collecting, send everything off
            for destination, states in presence_to_send.items():
                self.federation_sender.send_presence(destination, states)

            for destination, edu_map in keyed_edus.items():
                for key, edu in edu_map.items():
                    self.federation_sender.send_edu(
                        edu.destination, edu.edu_type, edu.content, key=key,
                    )

            for destination, edu_list in edus.items():
                for edu in edu_list:
                    self.federation_sender.send_edu(
                        edu.destination, edu.edu_type, edu.content, key=None,
                    )

            for destination, failure_list in failures.items():
                for failure in failure_list:
                    self.federation_sender.send_failure(destination, failure)

            for destination in device_destinations:
                self.federation_sender.send_device_messages(destination)

            # Record where we are in the stream.
            yield self.store.update_federation_out_pos(
                "federation", latest_id
            )

        # We also need to poke the federation sender when new events happen
        event_stream = result.get("events")
        if event_stream:
            latest_pos = event_stream["position"]
            self.federation_sender.notify_new_events(latest_pos)


if __name__ == '__main__':
    with LoggingContext("main"):
        start(sys.argv[1:])
