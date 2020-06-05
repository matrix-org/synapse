# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

import attr

from ._base import Config, ConfigError


@attr.s
class InstanceLocationConfig:
    """The host and port to talk to an instance via HTTP replication.
    """

    host = attr.ib(type=str)
    port = attr.ib(type=int)


@attr.s
class WriterLocations:
    """Specifies the instances that write various streams.

    Attributes:
        events: The instance that writes to the event and backfill streams.
    """

    events = attr.ib(default="master", type=str)


class WorkerConfig(Config):
    """The workers are processes run separately to the main synapse process.
    They have their own pid_file and listener configuration. They use the
    replication_url to talk to the main synapse process."""

    section = "worker"

    def read_config(self, config, **kwargs):
        self.worker_app = config.get("worker_app")

        # Canonicalise worker_app so that master always has None
        if self.worker_app == "synapse.app.homeserver":
            self.worker_app = None

        self.worker_listeners = config.get("worker_listeners", [])
        self.worker_daemonize = config.get("worker_daemonize")
        self.worker_pid_file = config.get("worker_pid_file")
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

        # A map from instance name to host/port of their HTTP replication endpoint.
        instance_map = config.get("instance_map") or {}
        self.instance_map = {
            name: InstanceLocationConfig(**c) for name, c in instance_map.items()
        }

        # Map from type of streams to source, c.f. WriterLocations.
        writers = config.get("stream_writers") or {}
        self.writers = WriterLocations(**writers)

        # Check that the configured writer for events also appears in
        # `instance_map`.
        if (
            self.writers.events != "master"
            and self.writers.events not in self.instance_map
        ):
            raise ConfigError(
                "Instance %r is configured to write events but does not appear in `instance_map` config."
                % (self.writers.events,)
            )

    def read_arguments(self, args):
        # We support a bunch of command line arguments that override options in
        # the config. A lot of these options have a worker_* prefix when running
        # on workers so we also have to override them when command line options
        # are specified.

        if args.daemonize is not None:
            self.worker_daemonize = args.daemonize
        if args.manhole is not None:
            self.worker_manhole = args.worker_manhole
