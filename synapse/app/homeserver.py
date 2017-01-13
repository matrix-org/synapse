#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

import gc
import logging
import os
import sys
from synapse.config._base import ConfigError

from synapse.python_dependencies import (
    check_requirements, DEPENDENCY_LINKS
)

from synapse.rest import ClientRestResource
from synapse.storage.engines import create_engine, IncorrectDatabaseSetup
from synapse.storage import are_all_users_on_domain
from synapse.storage.prepare_database import UpgradeDatabaseException, prepare_database

from synapse.server import HomeServer

from twisted.internet import reactor, task, defer
from twisted.application import service
from twisted.web.resource import Resource, EncodingResourceWrapper
from twisted.web.static import File
from twisted.web.server import GzipEncoderFactory
from synapse.http.server import RootRedirect
from synapse.rest.media.v0.content_repository import ContentRepoResource
from synapse.rest.media.v1.media_repository import MediaRepositoryResource
from synapse.rest.key.v1.server_key_resource import LocalKey
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.api.urls import (
    FEDERATION_PREFIX, WEB_CLIENT_PREFIX, CONTENT_REPO_PREFIX,
    SERVER_KEY_PREFIX, LEGACY_MEDIA_PREFIX, MEDIA_PREFIX, STATIC_PREFIX,
    SERVER_KEY_V2_PREFIX,
)
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.util.logcontext import LoggingContext
from synapse.metrics import register_memory_metrics, get_metrics_for
from synapse.metrics.resource import MetricsResource, METRICS_PREFIX
from synapse.replication.resource import ReplicationResource, REPLICATION_PREFIX
from synapse.federation.transport.server import TransportLayerServer

from synapse.util.rlimit import change_resource_limit
from synapse.util.versionstring import get_version_string
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.manhole import manhole

from synapse.http.site import SynapseSite

from synapse import events

from daemonize import Daemonize

logger = logging.getLogger("synapse.app.homeserver")


def gz_wrap(r):
    return EncodingResourceWrapper(r, [GzipEncoderFactory()])


def build_resource_for_web_client(hs):
    webclient_path = hs.get_config().web_client_location
    if not webclient_path:
        try:
            import syweb
        except ImportError:
            quit_with_error(
                "Could not find a webclient.\n\n"
                "Please either install the matrix-angular-sdk or configure\n"
                "the location of the source to serve via the configuration\n"
                "option `web_client_location`\n\n"
                "To install the `matrix-angular-sdk` via pip, run:\n\n"
                "    pip install '%(dep)s'\n"
                "\n"
                "You can also disable hosting of the webclient via the\n"
                "configuration option `web_client`\n"
                % {"dep": DEPENDENCY_LINKS["matrix-angular-sdk"]}
            )
        syweb_path = os.path.dirname(syweb.__file__)
        webclient_path = os.path.join(syweb_path, "webclient")
    # GZip is disabled here due to
    # https://twistedmatrix.com/trac/ticket/7678
    # (It can stay enabled for the API resources: they call
    # write() with the whole body and then finish() straight
    # after and so do not trigger the bug.
    # GzipFile was removed in commit 184ba09
    # return GzipFile(webclient_path)  # TODO configurable?
    return File(webclient_path)  # TODO configurable?


class SynapseHomeServer(HomeServer):
    def _listener_http(self, config, listener_config):
        port = listener_config["port"]
        bind_addresses = listener_config["bind_addresses"]
        tls = listener_config.get("tls", False)
        site_tag = listener_config.get("tag", port)

        if tls and config.no_tls:
            return

        resources = {}
        for res in listener_config["resources"]:
            for name in res["names"]:
                if name == "client":
                    client_resource = ClientRestResource(self)
                    if res["compress"]:
                        client_resource = gz_wrap(client_resource)

                    resources.update({
                        "/_matrix/client/api/v1": client_resource,
                        "/_matrix/client/r0": client_resource,
                        "/_matrix/client/unstable": client_resource,
                        "/_matrix/client/v2_alpha": client_resource,
                        "/_matrix/client/versions": client_resource,
                    })

                if name == "federation":
                    resources.update({
                        FEDERATION_PREFIX: TransportLayerServer(self),
                    })

                if name in ["static", "client"]:
                    resources.update({
                        STATIC_PREFIX: File(
                            os.path.join(os.path.dirname(synapse.__file__), "static")
                        ),
                    })

                if name in ["media", "federation", "client"]:
                    media_repo = MediaRepositoryResource(self)
                    resources.update({
                        MEDIA_PREFIX: media_repo,
                        LEGACY_MEDIA_PREFIX: media_repo,
                        CONTENT_REPO_PREFIX: ContentRepoResource(
                            self, self.config.uploads_path
                        ),
                    })

                if name in ["keys", "federation"]:
                    resources.update({
                        SERVER_KEY_PREFIX: LocalKey(self),
                        SERVER_KEY_V2_PREFIX: KeyApiV2Resource(self),
                    })

                if name == "webclient":
                    resources[WEB_CLIENT_PREFIX] = build_resource_for_web_client(self)

                if name == "metrics" and self.get_config().enable_metrics:
                    resources[METRICS_PREFIX] = MetricsResource(self)

                if name == "replication":
                    resources[REPLICATION_PREFIX] = ReplicationResource(self)

        if WEB_CLIENT_PREFIX in resources:
            root_resource = RootRedirect(WEB_CLIENT_PREFIX)
        else:
            root_resource = Resource()

        root_resource = create_resource_tree(resources, root_resource)

        if tls:
            for address in bind_addresses:
                reactor.listenSSL(
                    port,
                    SynapseSite(
                        "synapse.access.https.%s" % (site_tag,),
                        site_tag,
                        listener_config,
                        root_resource,
                    ),
                    self.tls_server_context_factory,
                    interface=address
                )
        else:
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
        logger.info("Synapse now listening on port %d", port)

    def start_listening(self):
        config = self.get_config()

        for listener in config.listeners:
            if listener["type"] == "http":
                self._listener_http(config, listener)
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

    def run_startup_checks(self, db_conn, database_engine):
        all_users_native = are_all_users_on_domain(
            db_conn.cursor(), database_engine, self.hostname
        )
        if not all_users_native:
            quit_with_error(
                "Found users in database not native to %s!\n"
                "You cannot changed a synapse server_name after it's been configured"
                % (self.hostname,)
            )

        try:
            database_engine.check_database(db_conn.cursor())
        except IncorrectDatabaseSetup as e:
            quit_with_error(e.message)

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


def quit_with_error(error_string):
    message_lines = error_string.split("\n")
    line_length = max([len(l) for l in message_lines if len(l) < 80]) + 2
    sys.stderr.write("*" * line_length + '\n')
    for line in message_lines:
        sys.stderr.write(" %s\n" % (line.rstrip(),))
    sys.stderr.write("*" * line_length + '\n')
    sys.exit(1)


def setup(config_options):
    """
    Args:
        config_options_options: The options passed to Synapse. Usually
            `sys.argv[1:]`.

    Returns:
        HomeServer
    """
    try:
        config = HomeServerConfig.load_or_generate_config(
            "Synapse Homeserver",
            config_options,
        )
    except ConfigError as e:
        sys.stderr.write("\n" + e.message + "\n")
        sys.exit(1)

    if not config:
        # If a config isn't returned, and an exception isn't raised, we're just
        # generating config files and shouldn't try to continue.
        sys.exit(0)

    config.setup_logging()

    # check any extra requirements we have now we have a config
    check_requirements(config)

    version_string = "Synapse/" + get_version_string(synapse)

    logger.info("Server hostname: %s", config.server_name)
    logger.info("Server version: %s", version_string)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    tls_server_context_factory = context_factory.ServerContextFactory(config)

    database_engine = create_engine(config.database_config)
    config.database_config["args"]["cp_openfun"] = database_engine.on_new_connection

    hs = SynapseHomeServer(
        config.server_name,
        db_config=config.database_config,
        tls_server_context_factory=tls_server_context_factory,
        config=config,
        version_string=version_string,
        database_engine=database_engine,
    )

    logger.info("Preparing database: %s...", config.database_config['name'])

    try:
        db_conn = hs.get_db_conn(run_new_connection=False)
        prepare_database(db_conn, database_engine, config=config)
        database_engine.on_new_connection(db_conn)

        hs.run_startup_checks(db_conn, database_engine)

        db_conn.commit()
    except UpgradeDatabaseException:
        sys.stderr.write(
            "\nFailed to upgrade database.\n"
            "Have you checked for version specific instructions in"
            " UPGRADES.rst?\n"
        )
        sys.exit(1)

    logger.info("Database prepared in %s.", config.database_config['name'])

    hs.setup()
    hs.start_listening()

    def start():
        hs.get_pusherpool().start()
        hs.get_state_handler().start_caching()
        hs.get_datastore().start_profiling()
        hs.get_datastore().start_doing_background_updates()
        hs.get_replication_layer().start_get_pdu_cache()

        register_memory_metrics(hs)

    reactor.callWhenRunning(start)

    return hs


class SynapseService(service.Service):
    """A twisted Service class that will start synapse. Used to run synapse
    via twistd and a .tac.
    """
    def __init__(self, config):
        self.config = config

    def startService(self):
        hs = setup(self.config)
        change_resource_limit(hs.config.soft_file_limit)
        if hs.config.gc_thresholds:
            gc.set_threshold(*hs.config.gc_thresholds)

    def stopService(self):
        return self._port.stopListening()


def run(hs):
    PROFILE_SYNAPSE = False
    if PROFILE_SYNAPSE:
        def profile(func):
            from cProfile import Profile
            from threading import current_thread

            def profiled(*args, **kargs):
                profile = Profile()
                profile.enable()
                func(*args, **kargs)
                profile.disable()
                ident = current_thread().ident
                profile.dump_stats("/tmp/%s.%s.%i.pstat" % (
                    hs.hostname, func.__name__, ident
                ))

            return profiled

        from twisted.python.threadpool import ThreadPool
        ThreadPool._worker = profile(ThreadPool._worker)
        reactor.run = profile(reactor.run)

    start_time = hs.get_clock().time()

    stats = {}

    @defer.inlineCallbacks
    def phone_stats_home():
        logger.info("Gathering stats for reporting")
        now = int(hs.get_clock().time())
        uptime = int(now - start_time)
        if uptime < 0:
            uptime = 0

        # If the stats directory is empty then this is the first time we've
        # reported stats.
        first_time = not stats

        stats["homeserver"] = hs.config.server_name
        stats["timestamp"] = now
        stats["uptime_seconds"] = uptime
        stats["total_users"] = yield hs.get_datastore().count_all_users()

        room_count = yield hs.get_datastore().get_room_count()
        stats["total_room_count"] = room_count

        stats["daily_active_users"] = yield hs.get_datastore().count_daily_users()
        daily_messages = yield hs.get_datastore().count_daily_messages()
        if daily_messages is not None:
            stats["daily_messages"] = daily_messages
        else:
            stats.pop("daily_messages", None)

        if first_time:
            # Add callbacks to report the synapse stats as metrics whenever
            # prometheus requests them, typically every 30s.
            # As some of the stats are expensive to calculate we only update
            # them when synapse phones home to matrix.org every 24 hours.
            metrics = get_metrics_for("synapse.usage")
            metrics.add_callback("timestamp", lambda: stats["timestamp"])
            metrics.add_callback("uptime_seconds", lambda: stats["uptime_seconds"])
            metrics.add_callback("total_users", lambda: stats["total_users"])
            metrics.add_callback("total_room_count", lambda: stats["total_room_count"])
            metrics.add_callback(
                "daily_active_users", lambda: stats["daily_active_users"]
            )
            metrics.add_callback(
                "daily_messages", lambda: stats.get("daily_messages", 0)
            )

        logger.info("Reporting stats to matrix.org: %s" % (stats,))
        try:
            yield hs.get_simple_http_client().put_json(
                "https://matrix.org/report-usage-stats/push",
                stats
            )
        except Exception as e:
            logger.warn("Error reporting stats: %s", e)

    if hs.config.report_stats:
        phone_home_task = task.LoopingCall(phone_stats_home)
        logger.info("Scheduling stats reporting for 24 hour intervals")
        phone_home_task.start(60 * 60 * 24, now=False)

    def in_thread():
        # Uncomment to enable tracing of log context changes.
        # sys.settrace(logcontext_tracer)
        with LoggingContext("run"):
            change_resource_limit(hs.config.soft_file_limit)
            if hs.config.gc_thresholds:
                gc.set_threshold(*hs.config.gc_thresholds)
            reactor.run()

    if hs.config.daemonize:

        if hs.config.print_pidfile:
            print (hs.config.pid_file)

        daemon = Daemonize(
            app="synapse-homeserver",
            pid=hs.config.pid_file,
            action=lambda: in_thread(),
            auto_close_fds=False,
            verbose=True,
            logger=logger,
        )

        daemon.start()
    else:
        in_thread()


def main():
    with LoggingContext("main"):
        # check base requirements
        check_requirements()
        hs = setup(sys.argv[1:])
        run(hs)


if __name__ == '__main__':
    main()
