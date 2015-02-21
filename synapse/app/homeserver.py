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

from synapse.storage import prepare_database, UpgradeDatabaseException

from synapse.server import HomeServer

from synapse.python_dependencies import check_requirements

from twisted.internet import reactor
from twisted.enterprise import adbapi
from twisted.web.resource import Resource
from twisted.web.static import File
from twisted.web.server import Site
from synapse.http.server import JsonResource, RootRedirect
from synapse.rest.appservice.v1 import AppServiceRestResource
from synapse.rest.media.v0.content_repository import ContentRepoResource
from synapse.rest.media.v1.media_repository import MediaRepositoryResource
from synapse.http.server_key_resource import LocalKey
from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.api.urls import (
    CLIENT_PREFIX, FEDERATION_PREFIX, WEB_CLIENT_PREFIX, CONTENT_REPO_PREFIX,
    SERVER_KEY_PREFIX, MEDIA_PREFIX, CLIENT_V2_ALPHA_PREFIX, APP_SERVICE_PREFIX
)
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.util.logcontext import LoggingContext
from synapse.rest.client.v1 import ClientV1RestResource
from synapse.rest.client.v2_alpha import ClientV2AlphaRestResource

from daemonize import Daemonize
import twisted.manhole.telnet

import synapse

import logging
import os
import re
import subprocess
import sqlite3
import syweb

logger = logging.getLogger(__name__)


class SynapseHomeServer(HomeServer):

    def build_http_client(self):
        return MatrixFederationHttpClient(self)

    def build_resource_for_client(self):
        return ClientV1RestResource(self)

    def build_resource_for_client_v2_alpha(self):
        return ClientV2AlphaRestResource(self)

    def build_resource_for_federation(self):
        return JsonResource(self)

    def build_resource_for_app_services(self):
        return AppServiceRestResource(self)

    def build_resource_for_web_client(self):
        syweb_path = os.path.dirname(syweb.__file__)
        webclient_path = os.path.join(syweb_path, "webclient")
        return File(webclient_path)  # TODO configurable?

    def build_resource_for_content_repo(self):
        return ContentRepoResource(
            self, self.upload_dir, self.auth, self.content_addr
        )

    def build_resource_for_media_repository(self):
        return MediaRepositoryResource(self)

    def build_resource_for_server_key(self):
        return LocalKey(self)

    def build_db_pool(self):
        return adbapi.ConnectionPool(
            "sqlite3", self.get_db_name(),
            check_same_thread=False,
            cp_min=1,
            cp_max=1,
            cp_openfun=prepare_database,  # Prepare the database for each conn
                                          # so that :memory: sqlite works
        )

    def create_resource_tree(self, web_client, redirect_root_to_web_client):
        """Create the resource tree for this Home Server.

        This in unduly complicated because Twisted does not support putting
        child resources more than 1 level deep at a time.

        Args:
            web_client (bool): True to enable the web client.
            redirect_root_to_web_client (bool): True to redirect '/' to the
            location of the web client. This does nothing if web_client is not
            True.
        """
        # list containing (path_str, Resource) e.g:
        # [ ("/aaa/bbb/cc", Resource1), ("/aaa/dummy", Resource2) ]
        desired_tree = [
            (CLIENT_PREFIX, self.get_resource_for_client()),
            (CLIENT_V2_ALPHA_PREFIX, self.get_resource_for_client_v2_alpha()),
            (FEDERATION_PREFIX, self.get_resource_for_federation()),
            (CONTENT_REPO_PREFIX, self.get_resource_for_content_repo()),
            (SERVER_KEY_PREFIX, self.get_resource_for_server_key()),
            (MEDIA_PREFIX, self.get_resource_for_media_repository()),
            (APP_SERVICE_PREFIX, self.get_resource_for_app_services()),
        ]
        if web_client:
            logger.info("Adding the web client.")
            desired_tree.append((WEB_CLIENT_PREFIX,
                                self.get_resource_for_web_client()))

        if web_client and redirect_root_to_web_client:
            self.root_resource = RootRedirect(WEB_CLIENT_PREFIX)
        else:
            self.root_resource = Resource()

        # ideally we'd just use getChild and putChild but getChild doesn't work
        # unless you give it a Request object IN ADDITION to the name :/ So
        # instead, we'll store a copy of this mapping so we can actually add
        # extra resources to existing nodes. See self._resource_id for the key.
        resource_mappings = {}
        for (full_path, resource) in desired_tree:
            logger.info("Attaching %s to path %s", resource, full_path)
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
                    resource.putChild(child_name, child_resource)

            # finally, insert the desired resource in the right place
            last_resource.putChild(last_path_seg, resource)
            res_id = self._resource_id(last_resource, last_path_seg)
            resource_mappings[res_id] = resource

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

    def start_listening(self, secure_port, unsecure_port):
        if secure_port is not None:
            reactor.listenSSL(
                secure_port, Site(self.root_resource), self.tls_context_factory
            )
            logger.info("Synapse now listening on port %d", secure_port)
        if unsecure_port is not None:
            reactor.listenTCP(
                unsecure_port, Site(self.root_resource)
            )
            logger.info("Synapse now listening on port %d", unsecure_port)


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


def setup():
    config = HomeServerConfig.load_config(
        "Synapse Homeserver",
        sys.argv[1:],
        generate_section="Homeserver"
    )

    config.setup_logging()

    check_requirements()

    version_string = get_version_string()

    logger.info("Server hostname: %s", config.server_name)
    logger.info("Server version: %s", version_string)

    if re.search(":[0-9]+$", config.server_name):
        domain_with_port = config.server_name
    else:
        domain_with_port = "%s:%s" % (config.server_name, config.bind_port)

    tls_context_factory = context_factory.ServerContextFactory(config)

    hs = SynapseHomeServer(
        config.server_name,
        domain_with_port=domain_with_port,
        upload_dir=os.path.abspath("uploads"),
        db_name=config.database_path,
        tls_context_factory=tls_context_factory,
        config=config,
        content_addr=config.content_addr,
        version_string=version_string,
    )

    hs.create_resource_tree(
        web_client=config.webclient,
        redirect_root_to_web_client=True,
    )

    db_name = hs.get_db_name()

    logger.info("Preparing database: %s...", db_name)

    try:
        with sqlite3.connect(db_name) as db_conn:
            prepare_database(db_conn)
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

    bind_port = config.bind_port
    if config.no_tls:
        bind_port = None

    hs.start_listening(bind_port, config.unsecure_port)

    hs.get_pusherpool().start()
    hs.get_state_handler().start_caching()
    hs.get_datastore().start_profiling()
    hs.get_replication_layer().start_get_pdu_cache()

    if config.daemonize:
        print config.pid_file
        daemon = Daemonize(
            app="synapse-homeserver",
            pid=config.pid_file,
            action=run,
            auto_close_fds=False,
            verbose=True,
            logger=logger,
        )

        daemon.start()
    else:
        reactor.run()


def run():
    with LoggingContext("run"):
        reactor.run()


def main():
    with LoggingContext("main"):
        check_requirements()
        setup()


if __name__ == '__main__':
    main()
