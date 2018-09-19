#!/usr/bin/env python
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
from synapse.crypto import context_factory
from synapse.http.server import JsonResource
from synapse.http.site import SynapseSite
from synapse.metrics import RegistryProxy
from synapse.metrics.resource import METRICS_PREFIX, MetricsResource
from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.client_ips import SlavedClientIpStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.rest.client.v2_alpha import user_directory
from synapse.server import HomeServer
from synapse.storage.engines import create_engine
from synapse.storage.user_directory import UserDirectoryStore
from synapse.util.caches.stream_change_cache import StreamChangeCache
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext, run_in_background
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.user_dir")


class UserDirectorySlaveStore(
    SlavedEventStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    SlavedClientIpStore,
    UserDirectoryStore,
    BaseSlavedStore,
):
    def __init__(self, db_conn, hs):
        super(UserDirectorySlaveStore, self).__init__(db_conn, hs)

        events_max = self._stream_id_gen.get_current_token()
        curr_state_delta_prefill, min_curr_state_delta_id = self._get_cache_dict(
            db_conn, "current_state_delta_stream",
            entity_column="room_id",
            stream_column="stream_id",
            max_value=events_max,  # As we share the stream id with events token
            limit=1000,
        )
        self._curr_state_delta_stream_cache = StreamChangeCache(
            "_curr_state_delta_stream_cache", min_curr_state_delta_id,
            prefilled_cache=curr_state_delta_prefill,
        )

        self._current_state_delta_pos = events_max

    def stream_positions(self):
        result = super(UserDirectorySlaveStore, self).stream_positions()
        result["current_state_deltas"] = self._current_state_delta_pos
        return result

    def process_replication_rows(self, stream_name, token, rows):
        if stream_name == "current_state_deltas":
            self._current_state_delta_pos = token
            for row in rows:
                self._curr_state_delta_stream_cache.entity_has_changed(
                    row.room_id, token
                )
        return super(UserDirectorySlaveStore, self).process_replication_rows(
            stream_name, token, rows
        )


class UserDirectoryServer(HomeServer):
    DATASTORE_CLASS = UserDirectorySlaveStore

    def _listen_http(self, listener_config):
        port = listener_config["port"]
        bind_addresses = listener_config["bind_addresses"]
        site_tag = listener_config.get("tag", port)
        resources = {}
        for res in listener_config["resources"]:
            for name in res["names"]:
                if name == "metrics":
                    resources[METRICS_PREFIX] = MetricsResource(RegistryProxy)
                elif name == "client":
                    resource = JsonResource(self, canonical_json=False)
                    user_directory.register_servlets(self, resource)
                    resources.update({
                        "/_matrix/client/r0": resource,
                        "/_matrix/client/unstable": resource,
                        "/_matrix/client/v2_alpha": resource,
                        "/_matrix/client/api/v1": resource,
                    })

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
            )
        )

        logger.info("Synapse user_dir now listening on port %d", port)

    def start_listening(self, listeners):
        for listener in listeners:
            if listener["type"] == "http":
                self._listen_http(listener)
            elif listener["type"] == "manhole":
                _base.listen_tcp(
                    listener["bind_addresses"],
                    listener["port"],
                    manhole(
                        username="matrix",
                        password="rabbithole",
                        globals={"hs": self},
                    )
                )
            elif listener["type"] == "metrics":
                if not self.get_config().enable_metrics:
                    logger.warn(("Metrics listener configured, but "
                                 "enable_metrics is not True!"))
                else:
                    _base.listen_metrics(listener["bind_addresses"],
                                         listener["port"])
            else:
                logger.warn("Unrecognized listener type: %s", listener["type"])

        self.get_tcp_replication().start_replication(self)

    def build_tcp_replication(self):
        return UserDirectoryReplicationHandler(self)


class UserDirectoryReplicationHandler(ReplicationClientHandler):
    def __init__(self, hs):
        super(UserDirectoryReplicationHandler, self).__init__(hs.get_datastore())
        self.user_directory = hs.get_user_directory_handler()

    @defer.inlineCallbacks
    def on_rdata(self, stream_name, token, rows):
        yield super(UserDirectoryReplicationHandler, self).on_rdata(
            stream_name, token, rows
        )
        if stream_name == "current_state_deltas":
            run_in_background(self._notify_directory)

    @defer.inlineCallbacks
    def _notify_directory(self):
        try:
            yield self.user_directory.notify_new_event()
        except Exception:
            logger.exception("Error notifiying user directory of state update")


def start(config_options):
    try:
        config = HomeServerConfig.load_config(
            "Synapse user directory", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + e.message + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.user_dir"

    setup_logging(config, use_worker_options=True)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    database_engine = create_engine(config.database_config)

    if config.update_user_directory:
        sys.stderr.write(
            "\nThe update_user_directory must be disabled in the main synapse process"
            "\nbefore they can be run in a separate worker."
            "\nPlease add ``update_user_directory: false`` to the main config"
            "\n"
        )
        sys.exit(1)

    # Force the pushers to start since they will be disabled in the main config
    config.update_user_directory = True

    tls_server_context_factory = context_factory.ServerContextFactory(config)
    tls_client_options_factory = context_factory.ClientTLSOptionsFactory(config)

    ps = UserDirectoryServer(
        config.server_name,
        db_config=config.database_config,
        tls_server_context_factory=tls_server_context_factory,
        tls_client_options_factory=tls_client_options_factory,
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

    _base.start_worker_reactor("synapse-user-dir", config)


if __name__ == '__main__':
    with LoggingContext("main"):
        start(sys.argv[1:])
