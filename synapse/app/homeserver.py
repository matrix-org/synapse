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

import contextlib
import logging
import os
import re
import resource
import subprocess
import sys
import time
from synapse.config._base import ConfigError

from synapse.python_dependencies import (
    check_requirements, DEPENDENCY_LINKS
)

from synapse.rest import ClientRestResource
from synapse.storage.engines import create_engine, IncorrectDatabaseSetup
from synapse.storage import are_all_users_on_domain
from synapse.storage.prepare_database import UpgradeDatabaseException

from synapse.server import HomeServer


from twisted.conch.manhole import ColoredManhole
from twisted.conch.insults import insults
from twisted.conch import manhole_ssh
from twisted.cred import checkers, portal


from twisted.internet import reactor, task, defer
from twisted.application import service
from twisted.web.resource import Resource, EncodingResourceWrapper
from twisted.web.static import File
from twisted.web.server import Site, GzipEncoderFactory, Request
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
from synapse.metrics.resource import MetricsResource, METRICS_PREFIX
from synapse.replication.resource import ReplicationResource, REPLICATION_PREFIX
from synapse.federation.transport.server import TransportLayerServer

from synapse import events

from daemonize import Daemonize

logger = logging.getLogger("synapse.app.homeserver")


ACCESS_TOKEN_RE = re.compile(r'(\?.*access(_|%5[Ff])token=)[^&]*(.*)$')


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
        bind_address = listener_config.get("bind_address", "")
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
                            self, self.config.uploads_path, self.auth, self.content_addr
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

        root_resource = create_resource_tree(resources)
        if tls:
            reactor.listenSSL(
                port,
                SynapseSite(
                    "synapse.access.https.%s" % (site_tag,),
                    site_tag,
                    listener_config,
                    root_resource,
                ),
                self.tls_server_context_factory,
                interface=bind_address
            )
        else:
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
        logger.info("Synapse now listening on port %d", port)

    def start_listening(self):
        config = self.get_config()

        for listener in config.listeners:
            if listener["type"] == "http":
                self._listener_http(config, listener)
            elif listener["type"] == "manhole":
                checker = checkers.InMemoryUsernamePasswordDatabaseDontUse(
                    matrix="rabbithole"
                )

                rlm = manhole_ssh.TerminalRealm()
                rlm.chainedProtocolFactory = lambda: insults.ServerProtocol(
                    ColoredManhole,
                    {
                        "__name__": "__console__",
                        "hs": self,
                    }
                )

                f = manhole_ssh.ConchFactory(portal.Portal(rlm, [checker]))

                reactor.listenTCP(
                    listener["port"],
                    f,
                    interface=listener.get("bind_address", '127.0.0.1')
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

    def get_db_conn(self):
        # Any param beginning with cp_ is a parameter for adbapi, and should
        # not be passed to the database engine.
        db_params = {
            k: v for k, v in self.db_config.get("args", {}).items()
            if not k.startswith("cp_")
        }
        db_conn = self.database_engine.module.connect(**db_params)

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


def get_version_string():
    try:
        null = open(os.devnull, 'w')
        cwd = os.path.dirname(os.path.abspath(__file__))
        try:
            git_branch = subprocess.check_output(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                stderr=null,
                cwd=cwd,
            ).strip()
            git_branch = "b=" + git_branch
        except subprocess.CalledProcessError:
            git_branch = ""

        try:
            git_tag = subprocess.check_output(
                ['git', 'describe', '--exact-match'],
                stderr=null,
                cwd=cwd,
            ).strip()
            git_tag = "t=" + git_tag
        except subprocess.CalledProcessError:
            git_tag = ""

        try:
            git_commit = subprocess.check_output(
                ['git', 'rev-parse', '--short', 'HEAD'],
                stderr=null,
                cwd=cwd,
            ).strip()
        except subprocess.CalledProcessError:
            git_commit = ""

        try:
            dirty_string = "-this_is_a_dirty_checkout"
            is_dirty = subprocess.check_output(
                ['git', 'describe', '--dirty=' + dirty_string],
                stderr=null,
                cwd=cwd,
            ).strip().endswith(dirty_string)

            git_dirty = "dirty" if is_dirty else ""
        except subprocess.CalledProcessError:
            git_dirty = ""

        if git_branch or git_tag or git_commit or git_dirty:
            git_version = ",".join(
                s for s in
                (git_branch, git_tag, git_commit, git_dirty,)
                if s
            )

            return (
                "Synapse/%s (%s)" % (
                    synapse.__version__, git_version,
                )
            ).encode("ascii")
    except Exception as e:
        logger.info("Failed to check for git repository: %s", e)

    return ("Synapse/%s" % (synapse.__version__,)).encode("ascii")


def change_resource_limit(soft_file_no):
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        if not soft_file_no:
            soft_file_no = hard

        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_file_no, hard))
        logger.info("Set file limit to: %d", soft_file_no)

        resource.setrlimit(
            resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
    except (ValueError, resource.error) as e:
        logger.warn("Failed to set file or core limit: %s", e)


def setup(config_options):
    """
    Args:
        config_options_options: The options passed to Synapse. Usually
            `sys.argv[1:]`.

    Returns:
        HomeServer
    """
    try:
        config = HomeServerConfig.load_config(
            "Synapse Homeserver",
            config_options,
            generate_section="Homeserver"
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

    version_string = get_version_string()

    logger.info("Server hostname: %s", config.server_name)
    logger.info("Server version: %s", version_string)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    tls_server_context_factory = context_factory.ServerContextFactory(config)

    database_engine = create_engine(config)
    config.database_config["args"]["cp_openfun"] = database_engine.on_new_connection

    hs = SynapseHomeServer(
        config.server_name,
        db_config=config.database_config,
        tls_server_context_factory=tls_server_context_factory,
        config=config,
        content_addr=config.content_addr,
        version_string=version_string,
        database_engine=database_engine,
    )

    logger.info("Preparing database: %s...", config.database_config['name'])

    try:
        db_conn = hs.get_db_conn()
        database_engine.prepare_database(db_conn)
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

    def stopService(self):
        return self._port.stopListening()


class SynapseRequest(Request):
    def __init__(self, site, *args, **kw):
        Request.__init__(self, *args, **kw)
        self.site = site
        self.authenticated_entity = None
        self.start_time = 0

    def __repr__(self):
        # We overwrite this so that we don't log ``access_token``
        return '<%s at 0x%x method=%s uri=%s clientproto=%s site=%s>' % (
            self.__class__.__name__,
            id(self),
            self.method,
            self.get_redacted_uri(),
            self.clientproto,
            self.site.site_tag,
        )

    def get_redacted_uri(self):
        return ACCESS_TOKEN_RE.sub(
            r'\1<redacted>\3',
            self.uri
        )

    def get_user_agent(self):
        return self.requestHeaders.getRawHeaders("User-Agent", [None])[-1]

    def started_processing(self):
        self.site.access_logger.info(
            "%s - %s - Received request: %s %s",
            self.getClientIP(),
            self.site.site_tag,
            self.method,
            self.get_redacted_uri()
        )
        self.start_time = int(time.time() * 1000)

    def finished_processing(self):

        try:
            context = LoggingContext.current_context()
            ru_utime, ru_stime = context.get_resource_usage()
            db_txn_count = context.db_txn_count
            db_txn_duration = context.db_txn_duration
        except:
            ru_utime, ru_stime = (0, 0)
            db_txn_count, db_txn_duration = (0, 0)

        self.site.access_logger.info(
            "%s - %s - {%s}"
            " Processed request: %dms (%dms, %dms) (%dms/%d)"
            " %sB %s \"%s %s %s\" \"%s\"",
            self.getClientIP(),
            self.site.site_tag,
            self.authenticated_entity,
            int(time.time() * 1000) - self.start_time,
            int(ru_utime * 1000),
            int(ru_stime * 1000),
            int(db_txn_duration * 1000),
            int(db_txn_count),
            self.sentLength,
            self.code,
            self.method,
            self.get_redacted_uri(),
            self.clientproto,
            self.get_user_agent(),
        )

    @contextlib.contextmanager
    def processing(self):
        self.started_processing()
        yield
        self.finished_processing()


class XForwardedForRequest(SynapseRequest):
    def __init__(self, *args, **kw):
        SynapseRequest.__init__(self, *args, **kw)

    """
    Add a layer on top of another request that only uses the value of an
    X-Forwarded-For header as the result of C{getClientIP}.
    """
    def getClientIP(self):
        """
        @return: The client address (the first address) in the value of the
            I{X-Forwarded-For header}.  If the header is not present, return
            C{b"-"}.
        """
        return self.requestHeaders.getRawHeaders(
            b"x-forwarded-for", [b"-"])[0].split(b",")[0].strip()


class SynapseRequestFactory(object):
    def __init__(self, site, x_forwarded_for):
        self.site = site
        self.x_forwarded_for = x_forwarded_for

    def __call__(self, *args, **kwargs):
        if self.x_forwarded_for:
            return XForwardedForRequest(self.site, *args, **kwargs)
        else:
            return SynapseRequest(self.site, *args, **kwargs)


class SynapseSite(Site):
    """
    Subclass of a twisted http Site that does access logging with python's
    standard logging
    """
    def __init__(self, logger_name, site_tag, config, resource, *args, **kwargs):
        Site.__init__(self, resource, *args, **kwargs)

        self.site_tag = site_tag

        proxied = config.get("x_forwarded", False)
        self.requestFactory = SynapseRequestFactory(self, proxied)
        self.access_logger = logging.getLogger(logger_name)

    def log(self, request):
        pass


def create_resource_tree(desired_tree, redirect_root_to_web_client=True):
    """Create the resource tree for this Home Server.

    This in unduly complicated because Twisted does not support putting
    child resources more than 1 level deep at a time.

    Args:
        web_client (bool): True to enable the web client.
        redirect_root_to_web_client (bool): True to redirect '/' to the
        location of the web client. This does nothing if web_client is not
        True.
    """
    if redirect_root_to_web_client and WEB_CLIENT_PREFIX in desired_tree:
        root_resource = RootRedirect(WEB_CLIENT_PREFIX)
    else:
        root_resource = Resource()

    # ideally we'd just use getChild and putChild but getChild doesn't work
    # unless you give it a Request object IN ADDITION to the name :/ So
    # instead, we'll store a copy of this mapping so we can actually add
    # extra resources to existing nodes. See self._resource_id for the key.
    resource_mappings = {}
    for full_path, res in desired_tree.items():
        logger.info("Attaching %s to path %s", res, full_path)
        last_resource = root_resource
        for path_seg in full_path.split('/')[1:-1]:
            if path_seg not in last_resource.listNames():
                # resource doesn't exist, so make a "dummy resource"
                child_resource = Resource()
                last_resource.putChild(path_seg, child_resource)
                res_id = _resource_id(last_resource, path_seg)
                resource_mappings[res_id] = child_resource
                last_resource = child_resource
            else:
                # we have an existing Resource, use that instead.
                res_id = _resource_id(last_resource, path_seg)
                last_resource = resource_mappings[res_id]

        # ===========================
        # now attach the actual desired resource
        last_path_seg = full_path.split('/')[-1]

        # if there is already a resource here, thieve its children and
        # replace it
        res_id = _resource_id(last_resource, last_path_seg)
        if res_id in resource_mappings:
            # there is a dummy resource at this path already, which needs
            # to be replaced with the desired resource.
            existing_dummy_resource = resource_mappings[res_id]
            for child_name in existing_dummy_resource.listNames():
                child_res_id = _resource_id(
                    existing_dummy_resource, child_name
                )
                child_resource = resource_mappings[child_res_id]
                # steal the children
                res.putChild(child_name, child_resource)

        # finally, insert the desired resource in the right place
        last_resource.putChild(last_path_seg, res)
        res_id = _resource_id(last_resource, last_path_seg)
        resource_mappings[res_id] = res

    return root_resource


def _resource_id(resource, path_seg):
    """Construct an arbitrary resource ID so you can retrieve the mapping
    later.

    If you want to represent resource A putChild resource B with path C,
    the mapping should looks like _resource_id(A,C) = B.

    Args:
        resource (Resource): The *parent* Resourceb
        path_seg (str): The name of the child Resource to be attached.
    Returns:
        str: A unique string which can be a key to the child Resource.
    """
    return "%s-%s" % (resource, path_seg)


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

    @defer.inlineCallbacks
    def phone_stats_home():
        logger.info("Gathering stats for reporting")
        now = int(hs.get_clock().time())
        uptime = int(now - start_time)
        if uptime < 0:
            uptime = 0

        stats = {}
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
