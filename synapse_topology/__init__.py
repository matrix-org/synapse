#! python
import argparse
import os.path as path
import sys

from synapse_topology.server import Server
from synapse_topology.model import Model

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


model = Model(args.config_dir)

server = Server(model)

server.app.run("localhost", 8888)
