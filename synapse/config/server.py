# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from ._base import Config, ConfigError


class ServerConfig(Config):

    def read_config(self, config):
        self.server_name = config["server_name"]
        self.pid_file = self.abspath(config.get("pid_file"))
        self.web_client = config["web_client"]
        self.web_client_location = config.get("web_client_location", None)
        self.soft_file_limit = config["soft_file_limit"]
        self.daemonize = config.get("daemonize")
        self.print_pidfile = config.get("print_pidfile")
        self.user_agent_suffix = config.get("user_agent_suffix")
        self.use_frozen_dicts = config.get("use_frozen_dicts", False)
        self.public_baseurl = config.get("public_baseurl")

        # Whether to send federation traffic out in this process. This only
        # applies to some federation traffic, and so shouldn't be used to
        # "disable" federation
        self.send_federation = config.get("send_federation", True)

        if self.public_baseurl is not None:
            if self.public_baseurl[-1] != '/':
                self.public_baseurl += '/'
        self.start_pushers = config.get("start_pushers", True)

        self.listeners = config.get("listeners", [])

        for listener in self.listeners:
            bind_address = listener.pop("bind_address", None)
            bind_addresses = listener.setdefault("bind_addresses", [])

            if bind_address:
                bind_addresses.append(bind_address)
            elif not bind_addresses:
                bind_addresses.append('')

        self.gc_thresholds = read_gc_thresholds(config.get("gc_thresholds", None))

        bind_port = config.get("bind_port")
        if bind_port:
            self.listeners = []
            bind_host = config.get("bind_host", "")
            gzip_responses = config.get("gzip_responses", True)

            names = ["client", "webclient"] if self.web_client else ["client"]

            self.listeners.append({
                "port": bind_port,
                "bind_addresses": [bind_host],
                "tls": True,
                "type": "http",
                "resources": [
                    {
                        "names": names,
                        "compress": gzip_responses,
                    },
                    {
                        "names": ["federation"],
                        "compress": False,
                    }
                ]
            })

            unsecure_port = config.get("unsecure_port", bind_port - 400)
            if unsecure_port:
                self.listeners.append({
                    "port": unsecure_port,
                    "bind_addresses": [bind_host],
                    "tls": False,
                    "type": "http",
                    "resources": [
                        {
                            "names": names,
                            "compress": gzip_responses,
                        },
                        {
                            "names": ["federation"],
                            "compress": False,
                        }
                    ]
                })

        manhole = config.get("manhole")
        if manhole:
            self.listeners.append({
                "port": manhole,
                "bind_addresses": ["127.0.0.1"],
                "type": "manhole",
            })

        metrics_port = config.get("metrics_port")
        if metrics_port:
            self.listeners.append({
                "port": metrics_port,
                "bind_addresses": [config.get("metrics_bind_host", "127.0.0.1")],
                "tls": False,
                "type": "http",
                "resources": [
                    {
                        "names": ["metrics"],
                        "compress": False,
                    },
                ]
            })

    def default_config(self, server_name, **kwargs):
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
        # This is also the last part of your UserID.
        server_name: "%(server_name)s"

        # When running as a daemon, the file to store the pid in
        pid_file: %(pid_file)s

        # Whether to serve a web client from the HTTP/HTTPS root resource.
        web_client: True

        # The public-facing base URL for the client API (not including _matrix/...)
        # public_baseurl: https://example.com:8448/

        # Set the soft limit on the number of file descriptors synapse can use
        # Zero is used to indicate synapse should set the soft limit to the
        # hard limit.
        soft_file_limit: 0

        # The GC threshold parameters to pass to `gc.set_threshold`, if defined
        # gc_thresholds: [700, 10, 10]

        # List of ports that Synapse should listen on, their purpose and their
        # configuration.
        listeners:
          # Main HTTPS listener
          # For when matrix traffic is sent directly to synapse.
          -
            # The port to listen for HTTPS requests on.
            port: %(bind_port)s

            # Local addresses to listen on.
            # This will listen on all IPv4 addresses by default.
            bind_addresses:
              - '0.0.0.0'
              # Uncomment to listen on all IPv6 interfaces
              # N.B: On at least Linux this will also listen on all IPv4
              # addresses, so you will need to comment out the line above.
              # - '::'

            # This is a 'http' listener, allows us to specify 'resources'.
            type: http

            tls: true

            # Use the X-Forwarded-For (XFF) header as the client IP and not the
            # actual client IP.
            x_forwarded: false

            # List of HTTP resources to serve on this listener.
            resources:
              -
                # List of resources to host on this listener.
                names:
                  - client     # The client-server APIs, both v1 and v2
                  - webclient  # The bundled webclient.

                # Should synapse compress HTTP responses to clients that support it?
                # This should be disabled if running synapse behind a load balancer
                # that can do automatic compression.
                compress: true

              - names: [federation]  # Federation APIs
                compress: false

          # Unsecure HTTP listener,
          # For when matrix traffic passes through loadbalancer that unwraps TLS.
          - port: %(unsecure_port)s
            tls: false
            bind_addresses: ['0.0.0.0']
            type: http

            x_forwarded: false

            resources:
              - names: [client, webclient]
                compress: true
              - names: [federation]
                compress: false

          # Turn on the twisted ssh manhole service on localhost on the given
          # port.
          # - port: 9000
          #   bind_address: 127.0.0.1
          #   type: manhole
        """ % locals()

    def read_arguments(self, args):
        if args.manhole is not None:
            self.manhole = args.manhole
        if args.daemonize is not None:
            self.daemonize = args.daemonize
        if args.print_pidfile is not None:
            self.print_pidfile = args.print_pidfile

    def add_arguments(self, parser):
        server_group = parser.add_argument_group("server")
        server_group.add_argument("-D", "--daemonize", action='store_true',
                                  default=None,
                                  help="Daemonize the home server")
        server_group.add_argument("--print-pidfile", action='store_true',
                                  default=None,
                                  help="Print the path to the pidfile just"
                                  " before daemonizing")
        server_group.add_argument("--manhole", metavar="PORT", dest="manhole",
                                  type=int,
                                  help="Turn on the twisted telnet manhole"
                                  " service on the given port.")


def read_gc_thresholds(thresholds):
    """Reads the three integer thresholds for garbage collection. Ensures that
    the thresholds are integers if thresholds are supplied.
    """
    if thresholds is None:
        return None
    try:
        assert len(thresholds) == 3
        return (
            int(thresholds[0]), int(thresholds[1]), int(thresholds[2]),
        )
    except:
        raise ConfigError(
            "Value of `gc_threshold` must be a list of three integers if set"
        )
