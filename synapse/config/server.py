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

import nacl.signing
import os
from ._base import Config
from syutil.base64util import encode_base64, decode_base64


class ServerConfig(Config):
    def __init__(self, args):
        super(ServerConfig, self).__init__(args)
        self.server_name = args.server_name
        self.signing_key = self.read_signing_key(args.signing_key_path)
        self.bind_port = args.bind_port
        self.bind_host = args.bind_host
        self.unsecure_port = args.unsecure_port
        self.daemonize = args.daemonize
        self.pid_file = self.abspath(args.pid_file)
        self.webclient = True
        self.manhole = args.manhole

        if not args.content_addr:
            host = args.server_name
            if ':' not in host:
                host  = "%s:%d" % (host, args.bind_port)
            args.content_addr = "https://%s" % (host,)

        self.content_addr = args.content_addr

    @classmethod
    def add_arguments(cls, parser):
        super(ServerConfig, cls).add_arguments(parser)
        server_group = parser.add_argument_group("server")
        server_group.add_argument("-H", "--server-name", default="localhost",
                                  help="The name of the server")
        server_group.add_argument("--signing-key-path",
                                  help="The signing key to sign messages with")
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
        server_group.add_argument("--manhole", metavar="PORT", dest="manhole",
                                  type=int,
                                  help="Turn on the twisted telnet manhole"
                                  " service on the given port.")
        server_group.add_argument("--content-addr", default=None,
                                  help="The host and scheme to use for the "
                                  "content repository")

    def read_signing_key(self, signing_key_path):
        signing_key_base64 = self.read_file(signing_key_path, "signing_key")
        signing_key_bytes = decode_base64(signing_key_base64)
        return nacl.signing.SigningKey(signing_key_bytes)

    @classmethod
    def generate_config(cls, args, config_dir_path):
        super(ServerConfig, cls).generate_config(args, config_dir_path)
        base_key_name = os.path.join(config_dir_path, args.server_name)

        args.pid_file = os.path.abspath(args.pid_file)

        if not args.signing_key_path:
            args.signing_key_path = base_key_name + ".signing.key"

        if not os.path.exists(args.signing_key_path):
            with open(args.signing_key_path, "w") as signing_key_file:
                key = nacl.signing.SigningKey.generate()
                signing_key_file.write(encode_base64(key.encode()))

