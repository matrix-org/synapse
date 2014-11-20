#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.storage import prepare_database

from synapse.server import HomeServer

from twisted.internet import reactor
from twisted.enterprise import adbapi
from twisted.web.resource import Resource
from twisted.web.static import File
from twisted.web.server import Site
from synapse.http.server import JsonResource, RootRedirect
from synapse.http.content_repository import ContentRepoResource
from synapse.http.server_key_resource import LocalKey
from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.api.urls import (
    CLIENT_PREFIX, FEDERATION_PREFIX, WEB_CLIENT_PREFIX, CONTENT_REPO_PREFIX,
    SERVER_KEY_PREFIX,
)
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.util.logcontext import LoggingContext

from daemonize import Daemonize
import twisted.manhole.telnet

import logging
import os
import re
import sys
import sqlite3
import syweb

logger = logging.getLogger(__name__)


class SynapseHomeServer(HomeServer):

    def build_http_client(self):
        return MatrixFederationHttpClient(self)

    def build_resource_for_client(self):
        return JsonResource()

    def build_resource_for_federation(self):
        return JsonResource()

    def build_resource_for_web_client(self):
        syweb_path = os.path.dirname(syweb.__file__)
        webclient_path = os.path.join(syweb_path, "webclient")
        return File(webclient_path)  # TODO configurable?

    def build_resource_for_content_repo(self):
        return ContentRepoResource(
            self, self.upload_dir, self.auth, self.content_addr
        )

    def build_resource_for_server_key(self):
        return LocalKey(self)

    def build_db_pool(self):
        return adbapi.ConnectionPool(
            "sqlite3", self.get_db_name(),
            check_same_thread=False,
            cp_min=1,
            cp_max=1
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
            (FEDERATION_PREFIX, self.get_resource_for_federation()),
            (CONTENT_REPO_PREFIX, self.get_resource_for_content_repo()),
            (SERVER_KEY_PREFIX, self.get_resource_for_server_key()),
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
                if not path_seg in last_resource.listNames():
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


def setup():
    config = HomeServerConfig.load_config(
        "Synapse Homeserver",
        sys.argv[1:],
        generate_section="Homeserver"
    )

    config.setup_logging()

    logger.info("Server hostname: %s", config.server_name)

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
    )

    hs.register_servlets()

    hs.create_resource_tree(
        web_client=config.webclient,
        redirect_root_to_web_client=True,
    )

    db_name = hs.get_db_name()

    logger.info("Preparing database: %s...", db_name)

    with sqlite3.connect(db_name) as db_conn:
        prepare_database(db_conn)

    logger.info("Database prepared in %s.", db_name)

    hs.get_db_pool()

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
        setup()


if __name__ == '__main__':
    main()
