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
import gc
import logging
import os
import sys

from six import iteritems

from prometheus_client import Gauge

from twisted.application import service
from twisted.internet import defer, reactor
from twisted.web.resource import EncodingResourceWrapper, NoResource
from twisted.web.server import GzipEncoderFactory
from twisted.web.static import File

import synapse
import synapse.config.logger
from synapse import events
from synapse.api.urls import (
    CONTENT_REPO_PREFIX,
    FEDERATION_PREFIX,
    LEGACY_MEDIA_PREFIX,
    MEDIA_PREFIX,
    SERVER_KEY_PREFIX,
    SERVER_KEY_V2_PREFIX,
    STATIC_PREFIX,
    WEB_CLIENT_PREFIX,
)
from synapse.app import _base
from synapse.app._base import listen_ssl, listen_tcp, quit_with_error
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.federation.transport.server import TransportLayerServer
from synapse.http.additional_resource import AdditionalResource
from synapse.http.server import RootRedirect
from synapse.http.site import SynapseSite
from synapse.metrics import RegistryProxy
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.metrics.resource import METRICS_PREFIX, MetricsResource
from synapse.module_api import ModuleApi
from synapse.python_dependencies import CONDITIONAL_REQUIREMENTS, check_requirements
from synapse.replication.http import REPLICATION_PREFIX, ReplicationRestResource
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.rest import ClientRestResource
from synapse.rest.key.v1.server_key_resource import LocalKey
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.rest.media.v0.content_repository import ContentRepoResource
from synapse.server import HomeServer
from synapse.storage import DataStore, are_all_users_on_domain
from synapse.storage.engines import IncorrectDatabaseSetup, create_engine
from synapse.storage.prepare_database import UpgradeDatabaseException, prepare_database
from synapse.util.caches import CACHE_SIZE_FACTOR
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext
from synapse.util.manhole import manhole
from synapse.util.module_loader import load_module
from synapse.util.rlimit import change_resource_limit
from synapse.util.versionstring import get_version_string

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
                % {"dep": CONDITIONAL_REQUIREMENTS["web_client"].keys()[0]}
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
    DATASTORE_CLASS = DataStore

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
                resources.update(self._configure_named_resource(
                    name, res.get("compress", False),
                ))

        additional_resources = listener_config.get("additional_resources", {})
        logger.debug("Configuring additional resources: %r",
                     additional_resources)
        module_api = ModuleApi(self, self.get_auth_handler())
        for path, resmodule in additional_resources.items():
            handler_cls, config = load_module(resmodule)
            handler = handler_cls(config, module_api)
            resources[path] = AdditionalResource(self, handler.handle_request)

        if WEB_CLIENT_PREFIX in resources:
            root_resource = RootRedirect(WEB_CLIENT_PREFIX)
        else:
            root_resource = NoResource()

        root_resource = create_resource_tree(resources, root_resource)

        if tls:
            listen_ssl(
                bind_addresses,
                port,
                SynapseSite(
                    "synapse.access.https.%s" % (site_tag,),
                    site_tag,
                    listener_config,
                    root_resource,
                    self.version_string,
                ),
                self.tls_server_context_factory,
            )

        else:
            listen_tcp(
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
        logger.info("Synapse now listening on port %d", port)

    def _configure_named_resource(self, name, compress=False):
        """Build a resource map for a named resource

        Args:
            name (str): named resource: one of "client", "federation", etc
            compress (bool): whether to enable gzip compression for this
                resource

        Returns:
            dict[str, Resource]: map from path to HTTP resource
        """
        resources = {}
        if name == "client":
            client_resource = ClientRestResource(self)
            if compress:
                client_resource = gz_wrap(client_resource)

            resources.update({
                "/_matrix/client/api/v1": client_resource,
                "/_matrix/client/r0": client_resource,
                "/_matrix/client/unstable": client_resource,
                "/_matrix/client/v2_alpha": client_resource,
                "/_matrix/client/versions": client_resource,
            })

        if name == "consent":
            from synapse.rest.consent.consent_resource import ConsentResource
            consent_resource = ConsentResource(self)
            if compress:
                consent_resource = gz_wrap(consent_resource)
            resources.update({
                "/_matrix/consent": consent_resource,
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
            if self.get_config().enable_media_repo:
                media_repo = self.get_media_repository_resource()
                resources.update({
                    MEDIA_PREFIX: media_repo,
                    LEGACY_MEDIA_PREFIX: media_repo,
                    CONTENT_REPO_PREFIX: ContentRepoResource(
                        self, self.config.uploads_path
                    ),
                })
            elif name == "media":
                raise ConfigError(
                    "'media' resource conflicts with enable_media_repo=False",
                )

        if name in ["keys", "federation"]:
            resources.update({
                SERVER_KEY_PREFIX: LocalKey(self),
                SERVER_KEY_V2_PREFIX: KeyApiV2Resource(self),
            })

        if name == "webclient":
            resources[WEB_CLIENT_PREFIX] = build_resource_for_web_client(self)

        if name == "metrics" and self.get_config().enable_metrics:
            resources[METRICS_PREFIX] = MetricsResource(RegistryProxy)

        if name == "replication":
            resources[REPLICATION_PREFIX] = ReplicationRestResource(self)

        return resources

    def start_listening(self):
        config = self.get_config()

        for listener in config.listeners:
            if listener["type"] == "http":
                self._listener_http(config, listener)
            elif listener["type"] == "manhole":
                listen_tcp(
                    listener["bind_addresses"],
                    listener["port"],
                    manhole(
                        username="matrix",
                        password="rabbithole",
                        globals={"hs": self},
                    )
                )
            elif listener["type"] == "replication":
                bind_addresses = listener["bind_addresses"]
                for address in bind_addresses:
                    factory = ReplicationStreamProtocolFactory(self)
                    server_listener = reactor.listenTCP(
                        listener["port"], factory, interface=address
                    )
                    reactor.addSystemEventTrigger(
                        "before", "shutdown", server_listener.stopListening,
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
            quit_with_error(str(e))


# Gauges to expose monthly active user control metrics
current_mau_gauge = Gauge("synapse_admin_mau:current", "Current MAU")
max_mau_gauge = Gauge("synapse_admin_mau:max", "MAU Limit")
registered_reserved_users_mau_gauge = Gauge(
    "synapse_admin_mau:registered_reserved_users",
    "Registered users with reserved threepids"
)


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
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    if not config:
        # If a config isn't returned, and an exception isn't raised, we're just
        # generating config files and shouldn't try to continue.
        sys.exit(0)

    synapse.config.logger.setup_logging(config, use_worker_options=False)

    # check any extra requirements we have now we have a config
    check_requirements(config)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    tls_server_context_factory = context_factory.ServerContextFactory(config)
    tls_client_options_factory = context_factory.ClientTLSOptionsFactory(config)

    database_engine = create_engine(config.database_config)
    config.database_config["args"]["cp_openfun"] = database_engine.on_new_connection

    hs = SynapseHomeServer(
        config.server_name,
        db_config=config.database_config,
        tls_server_context_factory=tls_server_context_factory,
        tls_client_options_factory=tls_client_options_factory,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
    )

    logger.info("Preparing database: %s...", config.database_config['name'])

    try:
        with hs.get_db_conn(run_new_connection=False) as db_conn:
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
        hs.get_datastore().start_profiling()
        hs.get_datastore().start_doing_background_updates()

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

    clock = hs.get_clock()
    start_time = clock.time()

    stats = {}

    # Contains the list of processes we will be monitoring
    # currently either 0 or 1
    stats_process = []

    def start_phone_stats_home():
        return run_as_background_process("phone_stats_home", phone_stats_home)

    @defer.inlineCallbacks
    def phone_stats_home():
        logger.info("Gathering stats for reporting")
        now = int(hs.get_clock().time())
        uptime = int(now - start_time)
        if uptime < 0:
            uptime = 0

        stats["homeserver"] = hs.config.server_name
        stats["timestamp"] = now
        stats["uptime_seconds"] = uptime
        version = sys.version_info
        stats["python_version"] = "{}.{}.{}".format(
            version.major, version.minor, version.micro
        )
        stats["total_users"] = yield hs.get_datastore().count_all_users()

        total_nonbridged_users = yield hs.get_datastore().count_nonbridged_users()
        stats["total_nonbridged_users"] = total_nonbridged_users

        daily_user_type_results = yield hs.get_datastore().count_daily_user_type()
        for name, count in iteritems(daily_user_type_results):
            stats["daily_user_type_" + name] = count

        room_count = yield hs.get_datastore().get_room_count()
        stats["total_room_count"] = room_count

        stats["daily_active_users"] = yield hs.get_datastore().count_daily_users()
        stats["daily_active_rooms"] = yield hs.get_datastore().count_daily_active_rooms()
        stats["daily_messages"] = yield hs.get_datastore().count_daily_messages()

        r30_results = yield hs.get_datastore().count_r30_users()
        for name, count in iteritems(r30_results):
            stats["r30_users_" + name] = count

        daily_sent_messages = yield hs.get_datastore().count_daily_sent_messages()
        stats["daily_sent_messages"] = daily_sent_messages
        stats["cache_factor"] = CACHE_SIZE_FACTOR
        stats["event_cache_size"] = hs.config.event_cache_size

        if len(stats_process) > 0:
            stats["memory_rss"] = 0
            stats["cpu_average"] = 0
            for process in stats_process:
                stats["memory_rss"] += process.memory_info().rss
                stats["cpu_average"] += int(process.cpu_percent(interval=None))

        logger.info("Reporting stats to matrix.org: %s" % (stats,))
        try:
            yield hs.get_simple_http_client().put_json(
                "https://matrix.org/report-usage-stats/push",
                stats
            )
        except Exception as e:
            logger.warn("Error reporting stats: %s", e)

    def performance_stats_init():
        try:
            import psutil
            process = psutil.Process()
            # Ensure we can fetch both, and make the initial request for cpu_percent
            # so the next request will use this as the initial point.
            process.memory_info().rss
            process.cpu_percent(interval=None)
            logger.info("report_stats can use psutil")
            stats_process.append(process)
        except (ImportError, AttributeError):
            logger.warn(
                "report_stats enabled but psutil is not installed or incorrect version."
                " Disabling reporting of memory/cpu stats."
                " Ensuring psutil is available will help matrix.org track performance"
                " changes across releases."
            )

    def generate_user_daily_visit_stats():
        return run_as_background_process(
            "generate_user_daily_visits",
            hs.get_datastore().generate_user_daily_visits,
        )

    # Rather than update on per session basis, batch up the requests.
    # If you increase the loop period, the accuracy of user_daily_visits
    # table will decrease
    clock.looping_call(generate_user_daily_visit_stats, 5 * 60 * 1000)

    # monthly active user limiting functionality
    clock.looping_call(
        hs.get_datastore().reap_monthly_active_users, 1000 * 60 * 60
    )
    hs.get_datastore().reap_monthly_active_users()

    @defer.inlineCallbacks
    def generate_monthly_active_users():
        current_mau_count = 0
        reserved_count = 0
        store = hs.get_datastore()
        if hs.config.limit_usage_by_mau:
            current_mau_count = yield store.get_monthly_active_count()
            reserved_count = yield store.get_registered_reserved_users_count()
        current_mau_gauge.set(float(current_mau_count))
        registered_reserved_users_mau_gauge.set(float(reserved_count))
        max_mau_gauge.set(float(hs.config.max_mau_value))

    hs.get_datastore().initialise_reserved_users(
        hs.config.mau_limits_reserved_threepids
    )
    generate_monthly_active_users()
    if hs.config.limit_usage_by_mau:
        clock.looping_call(generate_monthly_active_users, 5 * 60 * 1000)
    # End of monthly active user settings

    if hs.config.report_stats:
        logger.info("Scheduling stats reporting for 3 hour intervals")
        clock.looping_call(start_phone_stats_home, 3 * 60 * 60 * 1000)

        # We need to defer this init for the cases that we daemonize
        # otherwise the process ID we get is that of the non-daemon process
        clock.call_later(0, performance_stats_init)

        # We wait 5 minutes to send the first set of stats as the server can
        # be quite busy the first few minutes
        clock.call_later(5 * 60, start_phone_stats_home)

    if hs.config.daemonize and hs.config.print_pidfile:
        print (hs.config.pid_file)

    _base.start_reactor(
        "synapse-homeserver",
        hs.config.soft_file_limit,
        hs.config.gc_thresholds,
        hs.config.pid_file,
        hs.config.daemonize,
        hs.config.cpu_affinity,
        logger,
    )


def main():
    with LoggingContext("main"):
        # check base requirements
        check_requirements()
        hs = setup(sys.argv[1:])
        run(hs)


if __name__ == '__main__':
    main()
