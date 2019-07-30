#! python3
import argparse
import os.path as path
import sys

import synapse_topology.controller.server as server
import synapse_topology.model as model
import synapse_topology.view.server as webui_server

from twisted.internet import endpoints, reactor
from twisted.web.server import Site

from twisted.logger import (
    eventsFromJSONLogFile,
    textFileLogObserver,
    globalLogPublisher,
)

globalLogPublisher.addObserver(textFileLogObserver(sys.stdout))

parser = argparse.ArgumentParser(description="Synapse configuration util")
parser.add_argument(
    "config_dir",
    metavar="CONFIG_DIR",
    type=str,
    help="Path the directory containing synapse's configuration files.",
)


args = parser.parse_args()

if not path.isdir(args.config_dir):
    print("'{}' is not a directory.".format(args.config_dir))
    exit(1)


model.set_config_dir(args.config_dir)

# Backend

backend_endpoint = endpoints.serverFromString(
    reactor, "tcp6:port=8889:interface=localhost"
)
backend_endpoint.listen(Site(server.app.resource()))

# Frontend

frontend_endpoint = endpoints.serverFromString(
    reactor, "tcp6:port=8888:interface=localhost"
)
frontend_endpoint.listen(Site(webui_server.app.resource()))

reactor.run()
