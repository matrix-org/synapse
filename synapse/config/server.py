# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
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

import logging

from synapse.http.endpoint import parse_and_validate_server_name

from ._base import Config, ConfigError

logger = logging.Logger(__name__)


class ServerConfig(Config):

    def read_config(self, config):
        self.server_name = config["server_name"]

        try:
            parse_and_validate_server_name(self.server_name)
        except ValueError as e:
            raise ConfigError(str(e))

        self.pid_file = self.abspath(config.get("pid_file"))
        self.web_client = config["web_client"]
        self.web_client_location = config.get("web_client_location", None)
        self.soft_file_limit = config["soft_file_limit"]
        self.daemonize = config.get("daemonize")
        self.print_pidfile = config.get("print_pidfile")
        self.user_agent_suffix = config.get("user_agent_suffix")
        self.use_frozen_dicts = config.get("use_frozen_dicts", False)
        self.public_baseurl = config.get("public_baseurl")
        self.cpu_affinity = config.get("cpu_affinity")

        # Whether to send federation traffic out in this process. This only
        # applies to some federation traffic, and so shouldn't be used to
        # "disable" federation
        self.send_federation = config.get("send_federation", True)

        # Whether to enable user presence.
        self.use_presence = config.get("use_presence", True)

        # Whether to update the user directory or not. This should be set to
        # false only if we are updating the user directory in a worker
        self.update_user_directory = config.get("update_user_directory", True)

        # whether to enable the media repository endpoints. This should be set
        # to false if the media repository is running as a separate endpoint;
        # doing so ensures that we will not run cache cleanup jobs on the
        # master, potentially causing inconsistency.
        self.enable_media_repo = config.get("enable_media_repo", True)

        self.filter_timeline_limit = config.get("filter_timeline_limit", -1)

        # Whether we should block invites sent to users on this server
        # (other than those sent by local server admins)
        self.block_non_admin_invites = config.get(
            "block_non_admin_invites", False,
        )

        # Options to control access by tracking MAU
        self.limit_usage_by_mau = config.get("limit_usage_by_mau", False)
        self.max_mau_value = 0
        if self.limit_usage_by_mau:
            self.max_mau_value = config.get(
                "max_mau_value", 0,
            )

        self.mau_limits_reserved_threepids = config.get(
            "mau_limit_reserved_threepids", []
        )

        self.mau_trial_days = config.get(
            "mau_trial_days", 0,
        )

        # Options to disable HS
        self.hs_disabled = config.get("hs_disabled", False)
        self.hs_disabled_message = config.get("hs_disabled_message", "")
        self.hs_disabled_limit_type = config.get("hs_disabled_limit_type", "")

        # Admin uri to direct users at should their instance become blocked
        # due to resource constraints
        self.admin_contact = config.get("admin_contact", None)

        # FIXME: federation_domain_whitelist needs sytests
        self.federation_domain_whitelist = None
        federation_domain_whitelist = config.get(
            "federation_domain_whitelist", None
        )
        # turn the whitelist into a hash for speed of lookup
        if federation_domain_whitelist is not None:
            self.federation_domain_whitelist = {}
            for domain in federation_domain_whitelist:
                self.federation_domain_whitelist[domain] = True

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
            logger.warn(
                ("The metrics_port configuration option is deprecated in Synapse 0.31 "
                 "in favour of a listener. Please see "
                 "http://github.com/matrix-org/synapse/blob/master/docs/metrics-howto.rst"
                 " on how to configure the new listener."))

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
        _, bind_port = parse_and_validate_server_name(server_name)
        if bind_port is not None:
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

        # CPU affinity mask. Setting this restricts the CPUs on which the
        # process will be scheduled. It is represented as a bitmask, with the
        # lowest order bit corresponding to the first logical CPU and the
        # highest order bit corresponding to the last logical CPU. Not all CPUs
        # may exist on a given system but a mask may specify more CPUs than are
        # present.
        #
        # For example:
        #    0x00000001  is processor #0,
        #    0x00000003  is processors #0 and #1,
        #    0xFFFFFFFF  is all processors (#0 through #31).
        #
        # Pinning a Python process to a single CPU is desirable, because Python
        # is inherently single-threaded due to the GIL, and can suffer a
        # 30-40%% slowdown due to cache blow-out and thread context switching
        # if the scheduler happens to schedule the underlying threads across
        # different cores. See
        # https://www.mirantis.com/blog/improve-performance-python-programs-restricting-single-cpu/.
        #
        # This setting requires the affinity package to be installed!
        #
        # cpu_affinity: 0xFFFFFFFF

        # Whether to serve a web client from the HTTP/HTTPS root resource.
        web_client: True

        # The root directory to server for the above web client.
        # If left undefined, synapse will serve the matrix-angular-sdk web client.
        # Make sure matrix-angular-sdk is installed with pip if web_client is True
        # and web_client_location is undefined
        # web_client_location: "/path/to/web/root"

        # The public-facing base URL for the client API (not including _matrix/...)
        # public_baseurl: https://example.com:8448/

        # Set the soft limit on the number of file descriptors synapse can use
        # Zero is used to indicate synapse should set the soft limit to the
        # hard limit.
        soft_file_limit: 0

        # Set to false to disable presence tracking on this homeserver.
        use_presence: true

        # The GC threshold parameters to pass to `gc.set_threshold`, if defined
        # gc_thresholds: [700, 10, 10]

        # Set the limit on the returned events in the timeline in the get
        # and sync operations. The default value is -1, means no upper limit.
        # filter_timeline_limit: 5000

        # Whether room invites to users on this server should be blocked
        # (except those sent by local server admins). The default is False.
        # block_non_admin_invites: True

        # Restrict federation to the following whitelist of domains.
        # N.B. we recommend also firewalling your federation listener to limit
        # inbound federation traffic as early as possible, rather than relying
        # purely on this application-layer restriction.  If not specified, the
        # default is to whitelist everything.
        #
        # federation_domain_whitelist:
        #  - lon.example.com
        #  - nyc.example.com
        #  - syd.example.com

        # List of ports that Synapse should listen on, their purpose and their
        # configuration.
        listeners:
          # Main HTTPS listener
          # For when matrix traffic is sent directly to synapse.
          -
            # The port to listen for HTTPS requests on.
            port: %(bind_port)s

            # Local addresses to listen on.
            # On Linux and Mac OS, `::` will listen on all IPv4 and IPv6
            # addresses by default. For most other OSes, this will only listen
            # on IPv6.
            bind_addresses:
              - '::'
              - '0.0.0.0'

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

            # optional list of additional endpoints which can be loaded via
            # dynamic modules
            # additional_resources:
            #   "/_matrix/my/custom/endpoint":
            #     module: my_module.CustomRequestHandler
            #     config: {}

          # Unsecure HTTP listener,
          # For when matrix traffic passes through loadbalancer that unwraps TLS.
          - port: %(unsecure_port)s
            tls: false
            bind_addresses: ['::', '0.0.0.0']
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
          #   bind_addresses: ['::1', '127.0.0.1']
          #   type: manhole


          # Homeserver blocking
          #
          # How to reach the server admin, used in ResourceLimitError
          # admin_contact: 'mailto:admin@server.com'
          #
          # Global block config
          #
          # hs_disabled: False
          # hs_disabled_message: 'Human readable reason for why the HS is blocked'
          # hs_disabled_limit_type: 'error code(str), to help clients decode reason'
          #
          # Monthly Active User Blocking
          #
          # Enables monthly active user checking
          # limit_usage_by_mau: False
          # max_mau_value: 50
          # mau_trial_days: 2
          #
          # Sometimes the server admin will want to ensure certain accounts are
          # never blocked by mau checking. These accounts are specified here.
          #
          # mau_limit_reserved_threepids:
          # - medium: 'email'
          #   address: 'reserved_user@example.com'

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


def is_threepid_reserved(config, threepid):
    """Check the threepid against the reserved threepid config
    Args:
        config(ServerConfig) - to access server config attributes
        threepid(dict) - The threepid to test for

    Returns:
        boolean Is the threepid undertest reserved_user
    """

    for tp in config.mau_limits_reserved_threepids:
        if (threepid['medium'] == tp['medium']
                and threepid['address'] == tp['address']):
            return True
    return False


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
    except Exception:
        raise ConfigError(
            "Value of `gc_threshold` must be a list of three integers if set"
        )
