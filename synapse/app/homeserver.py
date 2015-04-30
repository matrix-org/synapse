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
sys.dont_write_bytecode = True
from synapse.python_dependencies import check_requirements

if __name__ == '__main__':
    check_requirements()

from synapse.storage.engines import create_engine, IncorrectDatabaseSetup
from synapse.storage import (
    are_all_users_on_domain, UpgradeDatabaseException,
)

from synapse.server import HomeServer


from twisted.internet import reactor
from twisted.application import service
from twisted.enterprise import adbapi
from twisted.web.resource import Resource
from twisted.web.static import File
from twisted.web.server import Site
from twisted.web.http import proxiedLogFormatter
from synapse.http.server import JsonResource, RootRedirect
from synapse.rest.media.v0.content_repository import ContentRepoResource
from synapse.rest.media.v1.media_repository import MediaRepositoryResource
from synapse.rest.key.v1.server_key_resource import LocalKey
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.api.urls import (
    CLIENT_PREFIX, FEDERATION_PREFIX, WEB_CLIENT_PREFIX, CONTENT_REPO_PREFIX,
    SERVER_KEY_PREFIX, MEDIA_PREFIX, CLIENT_V2_ALPHA_PREFIX, STATIC_PREFIX,
    SERVER_KEY_V2_PREFIX,
)
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.util.logcontext import LoggingContext
from synapse.rest.client.v1 import ClientV1RestResource
from synapse.rest.client.v2_alpha import ClientV2AlphaRestResource
from synapse.metrics.resource import MetricsResource, METRICS_PREFIX

from daemonize import Daemonize
import twisted.manhole.telnet

import synapse

import logging
import os
import re
import resource
import subprocess


logger = logging.getLogger("synapse.app.homeserver")


class SynapseHomeServer(HomeServer):

    def build_http_client(self):
        return MatrixFederationHttpClient(self)

    def build_resource_for_client(self):
        return ClientV1RestResource(self)

    def build_resource_for_client_v2_alpha(self):
        return ClientV2AlphaRestResource(self)

    def build_resource_for_federation(self):
        return JsonResource(self)

    def build_resource_for_web_client(self):
        import syweb
        syweb_path = os.path.dirname(syweb.__file__)
        webclient_path = os.path.join(syweb_path, "webclient")
        return File(webclient_path)  # TODO configurable?

    def build_resource_for_static_content(self):
        return File("static")

    def build_resource_for_content_repo(self):
        return ContentRepoResource(
            self, self.upload_dir, self.auth, self.content_addr
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

    def create_resource_tree(self, redirect_root_to_web_client):
        """Create the resource tree for this Home Server.

        This in unduly complicated because Twisted does not support putting
        child resources more than 1 level deep at a time.

        Args:
            web_client (bool): True to enable the web client.
            redirect_root_to_web_client (bool): True to redirect '/' to the
            location of the web client. This does nothing if web_client is not
            True.
        """
        config = self.get_config()
        web_client = config.web_client

        # list containing (path_str, Resource) e.g:
        # [ ("/aaa/bbb/cc", Resource1), ("/aaa/dummy", Resource2) ]
        desired_tree = [
            (CLIENT_PREFIX, self.get_resource_for_client()),
            (CLIENT_V2_ALPHA_PREFIX, self.get_resource_for_client_v2_alpha()),
            (FEDERATION_PREFIX, self.get_resource_for_federation()),
            (CONTENT_REPO_PREFIX, self.get_resource_for_content_repo()),
            (SERVER_KEY_PREFIX, self.get_resource_for_server_key()),
            (SERVER_KEY_V2_PREFIX, self.get_resource_for_server_key_v2()),
            (MEDIA_PREFIX, self.get_resource_for_media_repository()),
            (STATIC_PREFIX, self.get_resource_for_static_content()),
        ]

        if web_client:
            logger.info("Adding the web client.")
            desired_tree.append((WEB_CLIENT_PREFIX,
                                self.get_resource_for_web_client()))

        if web_client and redirect_root_to_web_client:
            self.root_resource = RootRedirect(WEB_CLIENT_PREFIX)
        else:
            self.root_resource = Resource()

        metrics_resource = self.get_resource_for_metrics()
        if config.metrics_port is None and metrics_resource is not None:
            desired_tree.append((METRICS_PREFIX, metrics_resource))

        # ideally we'd just use getChild and putChild but getChild doesn't work
        # unless you give it a Request object IN ADDITION to the name :/ So
        # instead, we'll store a copy of this mapping so we can actually add
        # extra resources to existing nodes. See self._resource_id for the key.
        resource_mappings = {}
        for full_path, res in desired_tree:
            logger.info("Attaching %s to path %s", res, full_path)
            last_resource = self.root_resource
            for path_seg in full_path.split('/')[1:-1]:
                if path_seg not in last_resource.listNames():
                    # resource doesn't exist, so make a "dummy resource"
                    child_resource = Resource()
                    last_resource.putChild(path_seg, child_resource)
                    res_id = self._resource_id(last_resource, path_seg)
                    resource_mappings[res_id] = child_resource
                    last_resource = child_resource
                else:
                    # we have an existing Resource, use that instead.
                    res_id = self._resource_id(last_resource, path_seg)
                    last_resource = resource_mappings[res_id]

            # ===========================
            # now attach the actual desired resource
            last_path_seg = full_path.split('/')[-1]

            # if there is already a resource here, thieve its children and
            # replace it
            res_id = self._resource_id(last_resource, last_path_seg)
            if res_id in resource_mappings:
                # there is a dummy resource at this path already, which needs
                # to be replaced with the desired resource.
                existing_dummy_resource = resource_mappings[res_id]
                for child_name in existing_dummy_resource.listNames():
                    child_res_id = self._resource_id(existing_dummy_resource,
                                                     child_name)
                    child_resource = resource_mappings[child_res_id]
                    # steal the children
                    res.putChild(child_name, child_resource)

            # finally, insert the desired resource in the right place
            last_resource.putChild(last_path_seg, res)
            res_id = self._resource_id(last_resource, last_path_seg)
            resource_mappings[res_id] = res

        return self.root_resource

    def _resource_id(self, resource, path_seg):
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

    def start_listening(self):
        config = self.get_config()

        log_formatter = None
        if config.captcha_ip_origin_is_x_forwarded:
            log_formatter = proxiedLogFormatter

        if not config.no_tls and config.bind_port is not None:
            reactor.listenSSL(
                config.bind_port,
                Site(
                    self.root_resource,
                    logPath=config.access_log_file,
                    logFormatter=log_formatter,
                ),
                self.tls_context_factory,
                interface=config.bind_host
            )
            logger.info("Synapse now listening on port %d", config.bind_port)

        if config.unsecure_port is not None:
            reactor.listenTCP(
                config.unsecure_port,
                Site(
                    self.root_resource,
                    logPath=config.access_log_file,
                    logFormatter=log_formatter,
                ),
                interface=config.bind_host
            )
            logger.info("Synapse now listening on port %d", config.unsecure_port)

        metrics_resource = self.get_resource_for_metrics()
        if metrics_resource and config.metrics_port is not None:
            reactor.listenTCP(
                config.metrics_port,
                Site(
                    metrics_resource,
                    logPath=config.access_log_file,
                    logFormatter=log_formatter,
                ),
                interface="127.0.0.1",
            )
            logger.info("Metrics now running on 127.0.0.1 port %d", config.metrics_port)

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
    line_length = max([len(l) for l in message_lines]) + 2
    sys.stderr.write("*" * line_length + '\n')
    for line in message_lines:
        if line.strip():
            sys.stderr.write(" %s\n" % (line.strip(),))
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
        logger.warn("Failed to check for git repository: %s", e)

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
        should_run (bool): Whether to start the reactor.

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

    if re.search(":[0-9]+$", config.server_name):
        domain_with_port = config.server_name
    else:
        domain_with_port = "%s:%s" % (config.server_name, config.bind_port)

    tls_context_factory = context_factory.ServerContextFactory(config)

    database_engine = create_engine(config.database_config["name"])
    config.database_config["args"]["cp_openfun"] = database_engine.on_new_connection

    hs = SynapseHomeServer(
        config.server_name,
        domain_with_port=domain_with_port,
        upload_dir=os.path.abspath("uploads"),
        db_name=config.database_path,
        db_config=config.database_config,
        tls_context_factory=tls_context_factory,
        config=config,
        content_addr=config.content_addr,
        version_string=version_string,
        database_engine=database_engine,
    )

    hs.create_resource_tree(
        redirect_root_to_web_client=True,
    )

    db_name = hs.get_db_name()

    logger.info("Preparing database: %s...", db_name)

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

    logger.info("Database prepared in %s.", db_name)

    if config.manhole:
        f = twisted.manhole.telnet.ShellFactory()
        f.username = "matrix"
        f.password = "rabbithole"
        f.namespace['hs'] = hs
        reactor.listenTCP(config.manhole, f, interface='127.0.0.1')

    hs.start_listening()

    hs.get_pusherpool().start()
    hs.get_state_handler().start_caching()
    hs.get_datastore().start_profiling()
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


def run(hs):

    def in_thread():
        with LoggingContext("run"):
            change_resource_limit(hs.config.soft_file_limit)

            reactor.run()

    if hs.config.daemonize:

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
