#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from synapse.storage import read_schema

from synapse.server import HomeServer

from twisted.internet import reactor
from twisted.enterprise import adbapi
from twisted.python.log import PythonLoggingObserver
from twisted.web.resource import Resource
from twisted.web.static import File
from twisted.web.server import Site
from synapse.http.server import JsonResource, RootRedirect
from synapse.http.client import TwistedHttpClient
from synapse.api.urls import CLIENT_PREFIX, FEDERATION_PREFIX, WEB_CLIENT_PREFIX

from daemonize import Daemonize

import argparse
import logging
import logging.config
import sqlite3

logger = logging.getLogger(__name__)


class SynapseHomeServer(HomeServer):

    def build_http_client(self):
        return TwistedHttpClient()

    def build_resource_for_client(self):
        return JsonResource()

    def build_resource_for_federation(self):
        return JsonResource()

    def build_resource_for_web_client(self):
        return File("webclient")  # TODO configurable?

    def build_db_pool(self):
        """ Set up all the dbs. Since all the *.sql have IF NOT EXISTS, so we
        don't have to worry about overwriting existing content.
        """
        logging.info("Preparing database: %s...", self.db_name)
        pool = adbapi.ConnectionPool(
            'sqlite3', self.db_name, check_same_thread=False,
            cp_min=1, cp_max=1)

        schemas = [
            "transactions",
            "pdu",
            "users",
            "profiles",
            "presence",
            "im",
            "room_aliases",
        ]

        for sql_loc in schemas:
            sql_script = read_schema(sql_loc)

            with sqlite3.connect(self.db_name) as db_conn:
                c = db_conn.cursor()
                c.executescript(sql_script)
                c.close()
                db_conn.commit()

        logging.info("Database prepared in %s.", self.db_name)

        return pool

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
            (FEDERATION_PREFIX, self.get_resource_for_federation())
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
            logging.info("Attaching %s to path %s", resource, full_path)
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

    def start_listening(self, port):
        reactor.listenTCP(port, Site(self.root_resource))


def setup_logging(verbosity=0, filename=None, config_path=None):
    """ Sets up logging with verbosity levels.

    Args:
        verbosity: The verbosity level.
        filename: Log to the given file rather than to the console.
        config_path: Path to a python logging config file.
    """

    if config_path is None:
        log_format = (
            '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s'
        )

        level = logging.INFO
        if verbosity:
            level = logging.DEBUG

        # FIXME: we need a logging.WARN for a -q quiet option

        logging.basicConfig(level=level, filename=filename, format=log_format)
    else:
        logging.config.fileConfig(config_path)

    observer = PythonLoggingObserver()
    observer.start()


def run():
    reactor.run()


def setup():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", dest="port", type=int, default=8080,
                        help="The port to listen on.")
    parser.add_argument("-d", "--database", dest="db", default="homeserver.db",
                        help="The database name.")
    parser.add_argument("-H", "--host", dest="host", default="localhost",
                        help="The hostname of the server.")
    parser.add_argument('-v', '--verbose', dest="verbose", action='count',
                        help="The verbosity level.")
    parser.add_argument('-f', '--log-file', dest="log_file", default=None,
                        help="File to log to.")
    parser.add_argument('--log-config', dest="log_config", default=None,
                        help="Python logging config")
    parser.add_argument('-D', '--daemonize', action='store_true',
                        default=False, help="Daemonize the home server")
    parser.add_argument('--pid-file', dest="pid", help="When running as a "
                        "daemon, the file to store the pid in",
                        default="hs.pid")
    parser.add_argument("-w", "--webclient", dest="webclient",
                        action="store_true", help="Host the web client.")
    args = parser.parse_args()

    verbosity = int(args.verbose) if args.verbose else None

    setup_logging(
        verbosity=verbosity,
        filename=args.log_file,
        config_path=args.log_config,
    )

    logger.info("Server hostname: %s", args.host)

    hs = SynapseHomeServer(
        args.host,
        db_name=args.db
    )

    # This object doesn't need to be saved because it's set as the handler for
    # the replication layer
    hs.get_federation()

    hs.register_servlets()

    hs.create_resource_tree(
        web_client=args.webclient,
        redirect_root_to_web_client=True)
    hs.start_listening(args.port)

    hs.build_db_pool()

    if args.daemonize:
        daemon = Daemonize(
            app="synapse-homeserver",
            pid=args.pid,
            action=run,
            auto_close_fds=False,
            verbose=True,
            logger=logger,
        )

        daemon.start()
    else:
        run()


if __name__ == '__main__':
    setup()
