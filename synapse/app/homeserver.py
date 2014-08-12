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
#!/usr/bin/env python

from synapse.storage import read_schema

from synapse.server import HomeServer

from twisted.internet import reactor
from twisted.enterprise import adbapi
from twisted.python.log import PythonLoggingObserver
from synapse.http.server import TwistedHttpServer
from synapse.http.client import TwistedHttpClient

from daemonize import Daemonize

import argparse
import logging
import logging.config
import sqlite3

logger = logging.getLogger(__name__)


class SynapseHomeServer(HomeServer):
    def build_http_server(self):
        return TwistedHttpServer()

    def build_http_client(self):
        return TwistedHttpClient()

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

        if not verbosity or verbosity == 0:
            level = logging.WARNING
        elif verbosity == 1:
            level = logging.INFO
        else:
            level = logging.DEBUG

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

    hs.get_http_server().start_listening(args.port)

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
