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

from ._base import Config


class ServerConfig(Config):

    def read_config(self, config):
        self.server_name = config["server_name"]
        self.bind_port = config["bind_port"]
        self.bind_host = config["bind_host"]
        self.unsecure_port = config["unsecure_port"]
        self.manhole = config.get("manhole")
        self.pid_file = self.abspath(config.get("pid_file"))
        self.web_client = config["web_client"]
        self.soft_file_limit = config["soft_file_limit"]
        self.daemonize = config.get("daemonize")
        self.use_frozen_dicts = config.get("use_frozen_dicts", True)

        # Attempt to guess the content_addr for the v0 content repostitory
        content_addr = config.get("content_addr")
        if not content_addr:
            host = self.server_name
            if ':' not in host:
                host = "%s:%d" % (host, self.unsecure_port)
            else:
                host = host.split(':')[0]
                host = "%s:%d" % (host, self.unsecure_port)
            content_addr = "http://%s" % (host,)

        self.content_addr = content_addr

    def default_config(self, config_dir_path, server_name):
        if ":" in server_name:
            bind_port = int(server_name.split(":")[1])
            unsecure_port = bind_port - 400
        else:
            bind_port = 8448
            unsecure_port = 8008

        pid_file = self.abspath("homeserver.pid")
        return """\
        ## Server ##

        # The domain name of the server, with optional explicit port.
        # This is used by remote servers to connect to this server,
        # e.g. matrix.org, localhost:8080, etc.
        server_name: "%(server_name)s"

        # The port to listen for HTTPS requests on.
        # For when matrix traffic is sent directly to synapse.
        bind_port: %(bind_port)s

        # The port to listen for HTTP requests on.
        # For when matrix traffic passes through loadbalancer that unwraps TLS.
        unsecure_port: %(unsecure_port)s

        # Local interface to listen on.
        # The empty string will cause synapse to listen on all interfaces.
        bind_host: ""

        # When running as a daemon, the file to store the pid in
        pid_file: %(pid_file)s

        # Whether to serve a web client from the HTTP/HTTPS root resource.
        web_client: True

        # Set the soft limit on the number of file descriptors synapse can use
        # Zero is used to indicate synapse should set the soft limit to the
        # hard limit.
        soft_file_limit: 0

        # Turn on the twisted telnet manhole service on localhost on the given
        # port.
        #manhole: 9000
        """ % locals()

    def read_arguments(self, args):
        if args.manhole is not None:
            self.manhole = args.manhole
        if args.daemonize is not None:
            self.daemonize = args.daemonize

    def add_arguments(self, parser):
        server_group = parser.add_argument_group("server")
        server_group.add_argument("-D", "--daemonize", action='store_true',
                                  default=None,
                                  help="Daemonize the home server")
        server_group.add_argument("--manhole", metavar="PORT", dest="manhole",
                                  type=int,
                                  help="Turn on the twisted telnet manhole"
                                  " service on the given port.")
