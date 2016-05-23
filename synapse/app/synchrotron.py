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

from synapse.config._base import ConfigError
from synapse.config.database import DatabaseConfig
from synapse.config.logger import LoggingConfig
from synapse.config.appservice import AppServiceConfig
from synapse.http.site import SynapseSite
from synapse.http.server import JsonResource
from synapse.metrics.resource import MetricsResource, METRICS_PREFIX
from synapse.rest.client.v2_alpha import sync
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.account_data import SlavedAccountDataStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.filtering import SlavedFilteringStore
from synapse.replication.slave.storage.push_rule import SlavedPushRuleStore
from synapse.server import HomeServer
from synapse.storage.engines import create_engine
from synapse.storage.roommember import RoomMemberStore
from synapse.util.async import sleep
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext
from synapse.util.manhole import manhole
from synapse.util.rlimit import change_resource_limit
from synapse.util.versionstring import get_version_string

from twisted.internet import reactor, defer
from twisted.web.resource import Resource

from daemonize import Daemonize

import sys
import logging
import contextlib

logger = logging.getLogger("synapse.app.synchrotron")


class SynchrotronConfig(DatabaseConfig, LoggingConfig, AppServiceConfig):
    def read_config(self, config):
        self.replication_url = config["replication_url"]
        self.server_name = config["server_name"]
        self.use_insecure_ssl_client_just_for_testing_do_not_use = config.get(
            "use_insecure_ssl_client_just_for_testing_do_not_use", False
        )
        self.user_agent_suffix = None
        self.listeners = config["listeners"]
        self.soft_file_limit = config.get("soft_file_limit")
        self.daemonize = config.get("daemonize")
        self.pid_file = self.abspath(config.get("pid_file"))
        self.macaroon_secret_key = config["macaroon_secret_key"]
        self.expire_access_token = config.get("expire_access_token", False)

    def default_config(self, server_name, **kwargs):
        pid_file = self.abspath("synchroton.pid")
        return """\
        # Slave configuration

        # The replication listener on the synapse to talk to.
        #replication_url: https://localhost:{replication_port}/_synapse/replication

        server_name: "%(server_name)s"

        listeners:
        # Enable a /sync listener on the synchrontron
        #- type: http
        #    port: {http_port}
        #    bind_address: ""
        # Enable a ssh manhole listener on the synchrotron
        # - type: manhole
        #   port: {manhole_port}
        #   bind_address: 127.0.0.1
        # Enable a metric listener on the synchrotron
        # - type: http
        #   port: {metrics_port}
        #   bind_address: 127.0.0.1
        #   resources:
        #    - names: ["metrics"]
        #      compress: False

        report_stats: False

        daemonize: False

        pid_file: %(pid_file)s
        """ % locals()


class SynchrotronSlavedStore(
    SlavedPushRuleStore,
    SlavedEventStore,
    SlavedReceiptsStore,
    SlavedAccountDataStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    SlavedFilteringStore,
):
    def get_current_presence_token(self):
        return 0

    presence_stream_cache = ()

    def get_presence_list_accepted(self, user_localpart):
        return ()

    def insert_client_ip(self, user, access_token, ip, user_agent):
        pass

    # XXX: This is a bit broken because we don't persist forgotten rooms
    # in a way that they can be streamed. This means that we don't have a
    # way to invalidate the forgotten rooms cache correctly.
    # For now we expire the cache every 10 minutes.
    BROKEN_CACHE_EXPIRY_MS = 60 * 60 * 1000
    who_forgot_in_room = (
        RoomMemberStore.__dict__["who_forgot_in_room"]
    )


class SynchrotronPresence(object):
    def set_state(self, user, state):
        pass

    def get_states(self, user_ids, as_event=False):
        return {}

    @contextlib.contextmanager
    def user_syncing(self, user, affect_presence):
        yield

    def current_state_for_users(self, user_ids):
        return {}


class SynchrotronTyping(object):
    _latest_room_serial = 0
    _room_serials = ()


class SynchrotronServer(HomeServer):
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
        self.datastore = SynchrotronSlavedStore(self.get_db_conn(), self)
        logger.info("Finished setting up.")

    def _listen_http(self, listener_config):
        port = listener_config["port"]
        bind_address = listener_config.get("bind_address", "")
        site_tag = listener_config.get("tag", port)
        resources = {}
        for res in listener_config["resources"]:
            for name in res["names"]:
                if name == "metrics":
                    resources[METRICS_PREFIX] = MetricsResource(self)
                elif name == "client":
                    resource = JsonResource(self, canonical_json=False)
                    sync.register_servlets(self, resource)
                    resources.update({
                        "/_matrix/client/r0": resource,
                        "/_matrix/client/unstable": resource,
                        "/_matrix/client/v2_alpha": resource,
                    })

        root_resource = create_resource_tree(resources, Resource())
        reactor.listenTCP(
            port,
            SynapseSite(
                "synapse.access.http.%s" % (site_tag,),
                site_tag,
                listener_config,
                root_resource,
            ),
            interface=bind_address
        )
        logger.info("Synapse synchrotron now listening on port %d", port)

    def start_listening(self):
        for listener in self.config.listeners:
            if listener["type"] == "http":
                self._listen_http(listener)
            elif listener["type"] == "manhole":
                reactor.listenTCP(
                    listener["port"],
                    manhole(
                        username="matrix",
                        password="rabbithole",
                        globals={"hs": self},
                    ),
                    interface=listener.get("bind_address", '127.0.0.1')
                )
            else:
                logger.warn("Unrecognized listener type: %s", listener["type"])

    @defer.inlineCallbacks
    def replicate(self):
        http_client = self.get_simple_http_client()
        store = self.get_datastore()
        replication_url = self.config.replication_url
        clock = self.get_clock()

        def expire_broken_caches():
            store.who_forgot_in_room.invalidate_all()

        next_expire_broken_caches_ms = 0
        while True:
            try:
                args = store.stream_positions()
                args["timeout"] = 30000
                result = yield http_client.get_json(replication_url, args=args)
                logger.error("FENRIS %r", result)
                now_ms = clock.time_msec()
                if now_ms > next_expire_broken_caches_ms:
                    expire_broken_caches()
                    next_expire_broken_caches_ms = (
                        now_ms + store.BROKEN_CACHE_EXPIRY_MS
                    )
                yield store.process_replication(result)
            except:
                logger.exception("Error replicating from %r", replication_url)
                sleep(5)


def setup(config_options):
    try:
        config = SynchrotronConfig.load_config(
            "Synapse synchrotron", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + e.message + "\n")
        sys.exit(1)

    if not config:
        sys.exit(0)

    config.setup_logging()

    database_engine = create_engine(config.database_config)

    ss = SynchrotronServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string=get_version_string("Synapse", synapse),
        database_engine=database_engine,
        presence_handler=SynchrotronPresence(),
        typing_handler=SynchrotronTyping(),
    )

    ss.setup()
    ss.start_listening()

    change_resource_limit(ss.config.soft_file_limit)

    def start():
        ss.get_datastore().start_profiling()
        ss.replicate()

    reactor.callWhenRunning(start)

    return ss


if __name__ == '__main__':
    with LoggingContext("main"):
        ps = setup(sys.argv[1:])

        if ps.config.daemonize:
            def run():
                with LoggingContext("run"):
                    change_resource_limit(ps.config.soft_file_limit)
                    reactor.run()

            daemon = Daemonize(
                app="synapse-pusher",
                pid=ps.config.pid_file,
                action=run,
                auto_close_fds=False,
                verbose=True,
                logger=logger,
            )

            daemon.start()
        else:
            reactor.run()
