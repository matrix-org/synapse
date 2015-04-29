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
    def __init__(self, args):
        super(ServerConfig, self).__init__(args)
        self.server_name = args.server_name
        self.bind_port = args.bind_port
        self.bind_host = args.bind_host
        self.unsecure_port = args.unsecure_port
        self.daemonize = args.daemonize
        self.pid_file = self.abspath(args.pid_file)
        self.web_client = args.web_client
        self.manhole = args.manhole
        self.soft_file_limit = args.soft_file_limit

        if not args.content_addr:
            host = args.server_name
            if ':' not in host:
                host = "%s:%d" % (host, args.unsecure_port)
            else:
                host = host.split(':')[0]
                host = "%s:%d" % (host, args.unsecure_port)
            args.content_addr = "http://%s" % (host,)

        self.content_addr = args.content_addr

    @classmethod
    def add_arguments(cls, parser):
        super(ServerConfig, cls).add_arguments(parser)
        server_group = parser.add_argument_group("server")
        server_group.add_argument(
            "-H", "--server-name", default="localhost",
            help="The domain name of the server, with optional explicit port. "
                 "This is used by remote servers to connect to this server, "
                 "e.g. matrix.org, localhost:8080, etc."
        )
        server_group.add_argument("-p", "--bind-port", metavar="PORT",
                                  type=int, help="https port to listen on",
                                  default=8448)
        server_group.add_argument("--unsecure-port", metavar="PORT",
                                  type=int, help="http port to listen on",
                                  default=8008)
        server_group.add_argument("--bind-host", default="",
                                  help="Local interface to listen on")
        server_group.add_argument("-D", "--daemonize", action='store_true',
                                  help="Daemonize the home server")
        server_group.add_argument('--pid-file', default="homeserver.pid",
                                  help="When running as a daemon, the file to"
                                  " store the pid in")
        server_group.add_argument('--web_client', default=True, type=bool,
                                  help="Whether or not to serve a web client")
        server_group.add_argument("--manhole", metavar="PORT", dest="manhole",
                                  type=int,
                                  help="Turn on the twisted telnet manhole"
                                  " service on the given port.")
        server_group.add_argument("--content-addr", default=None,
                                  help="The host and scheme to use for the "
                                  "content repository")
        server_group.add_argument("--soft-file-limit", type=int, default=0,
                                  help="Set the soft limit on the number of "
                                       "file descriptors synapse can use. "
                                       "Zero is used to indicate synapse "
                                       "should set the soft limit to the hard"
                                       "limit.")
