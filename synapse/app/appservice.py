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

import synapse
from synapse import events
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.http.site import SynapseSite
from synapse.metrics.resource import METRICS_PREFIX, MetricsResource
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.directory import DirectoryStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.server import HomeServer
from synapse.storage.engines import create_engine
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext, preserve_fn
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string
from twisted.internet import reactor
from twisted.web.resource import Resource

logger = logging.getLogger("synapse.app.appservice")


class AppserviceSlaveStore(
    DirectoryStore, SlavedEventStore, SlavedApplicationServiceStore,
    SlavedRegistrationStore,
):
    pass


class AppserviceServer(HomeServer):
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
        self.datastore = AppserviceSlaveStore(self.get_db_conn(), self)
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

        logger.info("Synapse appservice now listening on port %d", port)

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

        self.get_tcp_replication().start_replication(self)

    def build_tcp_replication(self):
        return ASReplicationHandler(self)


class ASReplicationHandler(ReplicationClientHandler):
    def __init__(self, hs):
        super(ASReplicationHandler, self).__init__(hs.get_datastore())
        self.appservice_handler = hs.get_application_service_handler()

    def on_rdata(self, stream_name, token, rows):
        super(ASReplicationHandler, self).on_rdata(stream_name, token, rows)

        if stream_name == "events":
            max_stream_id = self.store.get_room_max_stream_ordering()
            preserve_fn(
                self.appservice_handler.notify_interested_services
            )(max_stream_id)


def start(config_options):
    try:
        config = HomeServerConfig.load_config(
            "Synapse appservice", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + e.message + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.appservice"

    setup_logging(config, use_worker_options=True)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    database_engine = create_engine(config.database_config)

    if config.notify_appservices:
        sys.stderr.write(
            "\nThe appservices must be disabled in the main synapse process"
            "\nbefore they can be run in a separate worker."
            "\nPlease add ``notify_appservices: false`` to the main config"
            "\n"
        )
        sys.exit(1)

    # Force the pushers to start since they will be disabled in the main config
    config.notify_appservices = True

    ps = AppserviceServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
    )

    ps.setup()
    ps.start_listening(config.worker_listeners)

    def start():
        ps.get_datastore().start_profiling()
        ps.get_state_handler().start_caching()

    reactor.callWhenRunning(start)

    _base.start_worker_reactor("synapse-appservice", config)


if __name__ == '__main__':
    with LoggingContext("main"):
        start(sys.argv[1:])
