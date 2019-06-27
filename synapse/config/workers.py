# -*- coding: utf-8 -*-
# Copyright 2016 matrix.org
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


class WorkerConfig(Config):
    """The workers are processes run separately to the main synapse process.
    They have their own pid_file and listener configuration. They use the
    replication_url to talk to the main synapse process."""

    def read_config(self, config, **kwargs):
        self.worker_app = config.get("worker_app")

        # Canonicalise worker_app so that master always has None
        if self.worker_app == "synapse.app.homeserver":
            self.worker_app = None

        self.worker_listeners = config.get("worker_listeners", [])
        self.worker_daemonize = config.get("worker_daemonize")
        self.worker_pid_file = config.get("worker_pid_file")
        self.worker_log_file = config.get("worker_log_file")
        self.worker_log_config = config.get("worker_log_config")

        # The host used to connect to the main synapse
        self.worker_replication_host = config.get("worker_replication_host", None)

        # The port on the main synapse for TCP replication
        self.worker_replication_port = config.get("worker_replication_port", None)

        # The port on the main synapse for HTTP replication endpoint
        self.worker_replication_http_port = config.get("worker_replication_http_port")

        self.worker_name = config.get("worker_name", self.worker_app)

        self.worker_main_http_uri = config.get("worker_main_http_uri", None)

        # This option is really only here to support `--manhole` command line
        # argument.
        manhole = config.get("worker_manhole")
        if manhole:
            self.worker_listeners.append(
                {
                    "port": manhole,
                    "bind_addresses": ["127.0.0.1"],
                    "type": "manhole",
                    "tls": False,
                }
            )

        if self.worker_listeners:
            for listener in self.worker_listeners:
                bind_address = listener.pop("bind_address", None)
                bind_addresses = listener.setdefault("bind_addresses", [])

                if bind_address:
                    bind_addresses.append(bind_address)
                elif not bind_addresses:
                    bind_addresses.append("")

    def read_arguments(self, args):
        # We support a bunch of command line arguments that override options in
        # the config. A lot of these options have a worker_* prefix when running
        # on workers so we also have to override them when command line options
        # are specified.

        if args.daemonize is not None:
            self.worker_daemonize = args.daemonize
        if args.log_config is not None:
            self.worker_log_config = args.log_config
        if args.log_file is not None:
            self.worker_log_file = args.log_file
        if args.manhole is not None:
            self.worker_manhole = args.worker_manhole
