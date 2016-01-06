#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

import sys
from synapse.rest import ClientRestResource

sys.dont_write_bytecode = True
from synapse.python_dependencies import (
    check_requirements, DEPENDENCY_LINKS, MissingRequirementError
)

if __name__ == '__main__':
    try:
        check_requirements()
    except MissingRequirementError as e:
        message = "\n".join([
            "Missing Requirement: %s" % (e.message,),
            "To install run:",
            "    pip install --upgrade --force \"%s\"" % (e.dependency,),
            "",
        ])
        sys.stderr.writelines(message)
        sys.exit(1)

from synapse.storage.engines import create_engine, IncorrectDatabaseSetup
from synapse.storage import are_all_users_on_domain
from synapse.storage.prepare_database import UpgradeDatabaseException

from synapse.server import HomeServer


from twisted.internet import reactor, task, defer
from twisted.application import service
from twisted.enterprise import adbapi
from twisted.web.resource import Resource, EncodingResourceWrapper
from twisted.web.static import File
from twisted.web.server import Site, GzipEncoderFactory, Request
from synapse.http.server import JsonResource, RootRedirect
from synapse.rest.media.v0.content_repository import ContentRepoResource
from synapse.rest.media.v1.media_repository import MediaRepositoryResource
from synapse.rest.key.v1.server_key_resource import LocalKey
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.api.urls import (
    FEDERATION_PREFIX, WEB_CLIENT_PREFIX, CONTENT_REPO_PREFIX,
    SERVER_KEY_PREFIX, MEDIA_PREFIX, STATIC_PREFIX,
    SERVER_KEY_V2_PREFIX,
)
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.util.logcontext import LoggingContext
from synapse.metrics.resource import MetricsResource, METRICS_PREFIX

from synapse import events

from daemonize import Daemonize
import twisted.manhole.telnet

import synapse

import contextlib
import logging
import os
import re
import resource
import subprocess
import time


logger = logging.getLogger("synapse.app.homeserver")


def gz_wrap(r):
    return EncodingResourceWrapper(r, [GzipEncoderFactory()])


class SynapseHomeServer(HomeServer):

    def build_http_client(self):
        return MatrixFederationHttpClient(self)

    def build_client_resource(self):
        return ClientRestResource(self)

    def build_resource_for_federation(self):
        return JsonResource(self)

    def build_resource_for_web_client(self):
        webclient_path = self.get_config().web_client_location
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

    def build_resource_for_static_content(self):
        # This is old and should go away: not going to bother adding gzip
        return File(
            os.path.join(os.path.dirname(synapse.__file__), "static")
        )

    def build_resource_for_content_repo(self):
        return ContentRepoResource(
            self, self.config.uploads_path, self.auth, self.content_addr
        )

    def build_resource_for_media_repository(self):
        return MediaRepositoryResource(self)

    def build_resource_for_server_key(self):
        return LocalKey(self)

    def build_resource_for_server_key_v2(self):
        return KeyApiV2Resource(self)

    def build_resource_for_metrics(self):
        if self.get_config().enable_metrics:
            return MetricsResource(self)
        else:
            return None

    def build_db_pool(self):
        name = self.db_config["name"]

        return adbapi.ConnectionPool(
            name,
            **self.db_config.get("args", {})
        )

    def _listener_http(self, config, listener_config):
        port = listener_config["port"]
        bind_address = listener_config.get("bind_address", "")
        tls = listener_config.get("tls", False)
        site_tag = listener_config.get("tag", port)

        if tls and config.no_tls:
            return

        metrics_resource = self.get_resource_for_metrics()

        resources = {}
        for res in listener_config["resources"]:
            for name in res["names"]:
                if name == "client":
                    client_resource = self.get_client_resource()
                    if res["compress"]:
                        client_resource = gz_wrap(client_resource)

                    resources.update({
                        "/_matrix/client/api/v1": client_resource,
                        "/_matrix/client/r0": client_resource,
                        "/_matrix/client/unstable": client_resource,
                        "/_matrix/client/v2_alpha": client_resource,
                    })

                if name == "federation":
                    resources.update({
                        FEDERATION_PREFIX: self.get_resource_for_federation(),
                    })

                if name in ["static", "client"]:
                    resources.update({
                        STATIC_PREFIX: self.get_resource_for_static_content(),
                    })

                if name in ["media", "federation", "client"]:
                    resources.update({
                        MEDIA_PREFIX: self.get_resource_for_media_repository(),
                        CONTENT_REPO_PREFIX: self.get_resource_for_content_repo(),
                    })

                if name in ["keys", "federation"]:
                    resources.update({
                        SERVER_KEY_PREFIX: self.get_resource_for_server_key(),
                        SERVER_KEY_V2_PREFIX: self.get_resource_for_server_key_v2(),
                    })

                if name == "webclient":
                    resources[WEB_CLIENT_PREFIX] = self.get_resource_for_web_client()

                if name == "metrics" and metrics_resource:
                    resources[METRICS_PREFIX] = metrics_resource

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
                f = twisted.manhole.telnet.ShellFactory()
                f.username = "matrix"
                f.password = "rabbithole"
                f.namespace['hs'] = self
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
    except (ValueError, resource.error) as e:
        logger.warn("Failed to set file limit: %s", e)


def setup(config_options):
    """
    Args:
        config_options_options: The options passed to Synapse. Usually
            `sys.argv[1:]`.

    Returns:
        HomeServer
    """
    config = HomeServerConfig.load_config(
        "Synapse Homeserver",
        config_options,
        generate_section="Homeserver"
    )

    config.setup_logging()

    # check any extra requirements we have now we have a config
    check_requirements(config)

    version_string = get_version_string()

    logger.info("Server hostname: %s", config.server_name)
    logger.info("Server version: %s", version_string)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    tls_server_context_factory = context_factory.ServerContextFactory(config)

    database_engine = create_engine(config.database_config["name"])
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
        db_conn = database_engine.module.connect(
            **{
                k: v for k, v in config.database_config.get("args", {}).items()
                if not k.startswith("cp_")
            }
        )

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

    hs.start_listening()

    hs.get_pusherpool().start()
    hs.get_state_handler().start_caching()
    hs.get_datastore().start_profiling()
    hs.get_datastore().start_doing_background_updates()
    hs.get_replication_layer().start_get_pdu_cache()

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
        return re.sub(
            r'(\?.*access_token=)[^&]*(.*)$',
            r'\1<redacted>\2',
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
        resource (Resource): The *parent* Resource
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

        all_rooms = yield hs.get_datastore().get_rooms(False)
        stats["total_room_count"] = len(all_rooms)

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
        with LoggingContext("run"):
            change_resource_limit(hs.config.soft_file_limit)
            reactor.run()

    if hs.config.daemonize:

        if hs.config.print_pidfile:
            print hs.config.pid_file

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
