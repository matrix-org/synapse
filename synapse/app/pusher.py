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
from synapse.http.site import SynapseSite
from synapse.metrics import RegistryProxy
from synapse.metrics.resource import METRICS_PREFIX, MetricsResource
from synapse.replication.slave.storage.account_data import SlavedAccountDataStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.pushers import SlavedPusherStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.server import HomeServer
from synapse.storage import DataStore
from synapse.storage.engines import create_engine
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext, run_in_background
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.pusher")


class PusherSlaveStore(
    SlavedEventStore, SlavedPusherStore, SlavedReceiptsStore,
    SlavedAccountDataStore
):
    update_pusher_last_stream_ordering_and_success = (
        DataStore.update_pusher_last_stream_ordering_and_success.__func__
    )

    update_pusher_failing_since = (
        DataStore.update_pusher_failing_since.__func__
    )

    update_pusher_last_stream_ordering = (
        DataStore.update_pusher_last_stream_ordering.__func__
    )

    get_throttle_params_by_room = (
        DataStore.get_throttle_params_by_room.__func__
    )

    set_throttle_params = (
        DataStore.set_throttle_params.__func__
    )

    get_time_of_last_push_action_before = (
        DataStore.get_time_of_last_push_action_before.__func__
    )

    get_profile_displayname = (
        DataStore.get_profile_displayname.__func__
    )


class PusherServer(HomeServer):
    DATASTORE_CLASS = PusherSlaveStore

    def remove_pusher(self, app_id, push_key, user_id):
        self.get_tcp_replication().send_remove_pusher(app_id, push_key, user_id)

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
            )
        )

        logger.info("Synapse pusher now listening on port %d", port)

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
        return PusherReplicationHandler(self)


class PusherReplicationHandler(ReplicationClientHandler):
    def __init__(self, hs):
        super(PusherReplicationHandler, self).__init__(hs.get_datastore())

        self.pusher_pool = hs.get_pusherpool()

    @defer.inlineCallbacks
    def on_rdata(self, stream_name, token, rows):
        yield super(PusherReplicationHandler, self).on_rdata(stream_name, token, rows)
        run_in_background(self.poke_pushers, stream_name, token, rows)

    @defer.inlineCallbacks
    def poke_pushers(self, stream_name, token, rows):
        try:
            if stream_name == "pushers":
                for row in rows:
                    if row.deleted:
                        yield self.stop_pusher(row.user_id, row.app_id, row.pushkey)
                    else:
                        yield self.start_pusher(row.user_id, row.app_id, row.pushkey)
            elif stream_name == "events":
                self.pusher_pool.on_new_notifications(
                    token, token,
                )
            elif stream_name == "receipts":
                self.pusher_pool.on_new_receipts(
                    token, token, set(row.room_id for row in rows)
                )
        except Exception:
            logger.exception("Error poking pushers")

    def stop_pusher(self, user_id, app_id, pushkey):
        key = "%s:%s" % (app_id, pushkey)
        pushers_for_user = self.pusher_pool.pushers.get(user_id, {})
        pusher = pushers_for_user.pop(key, None)
        if pusher is None:
            return
        logger.info("Stopping pusher %r / %r", user_id, key)
        pusher.on_stop()

    def start_pusher(self, user_id, app_id, pushkey):
        key = "%s:%s" % (app_id, pushkey)
        logger.info("Starting pusher %r / %r", user_id, key)
        return self.pusher_pool._refresh_pusher(app_id, pushkey, user_id)


def start(config_options):
    try:
        config = HomeServerConfig.load_config(
            "Synapse pusher", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + e.message + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.pusher"

    setup_logging(config, use_worker_options=True)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    if config.start_pushers:
        sys.stderr.write(
            "\nThe pushers must be disabled in the main synapse process"
            "\nbefore they can be run in a separate worker."
            "\nPlease add ``start_pushers: false`` to the main config"
            "\n"
        )
        sys.exit(1)

    # Force the pushers to start since they will be disabled in the main config
    config.start_pushers = True

    database_engine = create_engine(config.database_config)

    ps = PusherServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
    )

    ps.setup()
    ps.start_listening(config.worker_listeners)

    def start():
        ps.get_pusherpool().start()
        ps.get_datastore().start_profiling()
        ps.get_state_handler().start_caching()

    reactor.callWhenRunning(start)

    _base.start_worker_reactor("synapse-pusher", config)


if __name__ == '__main__':
    with LoggingContext("main"):
        ps = start(sys.argv[1:])
