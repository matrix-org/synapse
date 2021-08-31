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

from typing import List, Union

import attr

from ._base import (
    Config,
    ConfigError,
    RoutableShardedWorkerHandlingConfig,
    ShardedWorkerHandlingConfig,
)
from .server import ListenerConfig, parse_listener_def

_FEDERATION_SENDER_WITH_SEND_FEDERATION_ENABLED_ERROR = """
The send_federation config option must be disabled in the main
synapse process before they can be run in a separate worker.

Please add ``send_federation: false`` to the main config
"""

_PUSHER_WITH_START_PUSHERS_ENABLED_ERROR = """
The start_pushers config option must be disabled in the main
synapse process before they can be run in a separate worker.

Please add ``start_pushers: false`` to the main config
"""


def _instance_to_list_converter(obj: Union[str, List[str]]) -> List[str]:
    """Helper for allowing parsing a string or list of strings to a config
    option expecting a list of strings.
    """

    if isinstance(obj, str):
        return [obj]
    return obj


@attr.s
class InstanceLocationConfig:
    """The host and port to talk to an instance via HTTP replication."""

    host = attr.ib(type=str)
    port = attr.ib(type=int)


@attr.s
class WriterLocations:
    """Specifies the instances that write various streams.

    Attributes:
        events: The instances that write to the event and backfill streams.
        typing: The instance that writes to the typing stream.
        to_device: The instances that write to the to_device stream. Currently
            can only be a single instance.
        account_data: The instances that write to the account data streams. Currently
            can only be a single instance.
        receipts: The instances that write to the receipts stream. Currently
            can only be a single instance.
        presence: The instances that write to the presence stream. Currently
            can only be a single instance.
    """

    events = attr.ib(
        default=["master"], type=List[str], converter=_instance_to_list_converter
    )
    typing = attr.ib(default="master", type=str)
    to_device = attr.ib(
        default=["master"],
        type=List[str],
        converter=_instance_to_list_converter,
    )
    account_data = attr.ib(
        default=["master"],
        type=List[str],
        converter=_instance_to_list_converter,
    )
    receipts = attr.ib(
        default=["master"],
        type=List[str],
        converter=_instance_to_list_converter,
    )
    presence = attr.ib(
        default=["master"],
        type=List[str],
        converter=_instance_to_list_converter,
    )


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

        self.worker_listeners = [
            parse_listener_def(x) for x in config.get("worker_listeners", [])
        ]
        self.worker_daemonize = config.get("worker_daemonize")
        self.worker_pid_file = config.get("worker_pid_file")
        self.worker_log_config = config.get("worker_log_config")

        # The host used to connect to the main synapse
        self.worker_replication_host = config.get("worker_replication_host", None)

        # The port on the main synapse for TCP replication
        self.worker_replication_port = config.get("worker_replication_port", None)

        # The port on the main synapse for HTTP replication endpoint
        self.worker_replication_http_port = config.get("worker_replication_http_port")

        # The shared secret used for authentication when connecting to the main synapse.
        self.worker_replication_secret = config.get("worker_replication_secret", None)

        self.worker_name = config.get("worker_name", self.worker_app)
        self.instance_name = self.worker_name or "master"

        self.worker_main_http_uri = config.get("worker_main_http_uri", None)

        # This option is really only here to support `--manhole` command line
        # argument.
        manhole = config.get("worker_manhole")
        if manhole:
            self.worker_listeners.append(
                ListenerConfig(
                    port=manhole,
                    bind_addresses=["127.0.0.1"],
                    type="manhole",
                )
            )

        # Handle federation sender configuration.
        #
        # There are two ways of configuring which instances handle federation
        # sending:
        #   1. The old way where "send_federation" is set to false and running a
        #      `synapse.app.federation_sender` worker app.
        #   2. Specifying the workers sending federation in
        #      `federation_sender_instances`.
        #

        send_federation = config.get("send_federation", True)

        federation_sender_instances = config.get("federation_sender_instances")
        if federation_sender_instances is None:
            # Default to an empty list, which means "another, unknown, worker is
            # responsible for it".
            federation_sender_instances = []

            # If no federation sender instances are set we check if
            # `send_federation` is set, which means use master
            if send_federation:
                federation_sender_instances = ["master"]

            if self.worker_app == "synapse.app.federation_sender":
                if send_federation:
                    # If we're running federation senders, and not using
                    # `federation_sender_instances`, then we should have
                    # explicitly set `send_federation` to false.
                    raise ConfigError(
                        _FEDERATION_SENDER_WITH_SEND_FEDERATION_ENABLED_ERROR
                    )

                federation_sender_instances = [self.worker_name]

        self.send_federation = self.instance_name in federation_sender_instances
        self.federation_shard_config = ShardedWorkerHandlingConfig(
            federation_sender_instances
        )

        # A map from instance name to host/port of their HTTP replication endpoint.
        instance_map = config.get("instance_map") or {}
        self.instance_map = {
            name: InstanceLocationConfig(**c) for name, c in instance_map.items()
        }

        # Map from type of streams to source, c.f. WriterLocations.
        writers = config.get("stream_writers") or {}
        self.writers = WriterLocations(**writers)

        # Check that the configured writers for events and typing also appears in
        # `instance_map`.
        for stream in (
            "events",
            "typing",
            "to_device",
            "account_data",
            "receipts",
            "presence",
        ):
            instances = _instance_to_list_converter(getattr(self.writers, stream))
            for instance in instances:
                if instance != "master" and instance not in self.instance_map:
                    raise ConfigError(
                        "Instance %r is configured to write %s but does not appear in `instance_map` config."
                        % (instance, stream)
                    )

        if len(self.writers.to_device) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `to_device` messages."
            )

        if len(self.writers.account_data) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `account_data` messages."
            )

        if len(self.writers.receipts) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `receipts` messages."
            )

        if len(self.writers.events) == 0:
            raise ConfigError("Must specify at least one instance to handle `events`.")

        if len(self.writers.presence) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `presence` messages."
            )

        self.events_shard_config = RoutableShardedWorkerHandlingConfig(
            self.writers.events
        )

        # Handle sharded push
        start_pushers = config.get("start_pushers", True)
        pusher_instances = config.get("pusher_instances")
        if pusher_instances is None:
            # Default to an empty list, which means "another, unknown, worker is
            # responsible for it".
            pusher_instances = []

            # If no pushers instances are set we check if `start_pushers` is
            # set, which means use master
            if start_pushers:
                pusher_instances = ["master"]

            if self.worker_app == "synapse.app.pusher":
                if start_pushers:
                    # If we're running pushers, and not using
                    # `pusher_instances`, then we should have explicitly set
                    # `start_pushers` to false.
                    raise ConfigError(_PUSHER_WITH_START_PUSHERS_ENABLED_ERROR)

                pusher_instances = [self.instance_name]

        self.start_pushers = self.instance_name in pusher_instances
        self.pusher_shard_config = ShardedWorkerHandlingConfig(pusher_instances)

        # Whether this worker should run background tasks or not.
        #
        # As a note for developers, the background tasks guarded by this should
        # be able to run on only a single instance (meaning that they don't
        # depend on any in-memory state of a particular worker).
        #
        # No effort is made to ensure only a single instance of these tasks is
        # running.
        background_tasks_instance = config.get("run_background_tasks_on") or "master"
        self.run_background_tasks = (
            self.worker_name is None and background_tasks_instance == "master"
        ) or self.worker_name == background_tasks_instance

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        ## Workers ##

        # Disables sending of outbound federation transactions on the main process.
        # Uncomment if using a federation sender worker.
        #
        #send_federation: false

        # It is possible to run multiple federation sender workers, in which case the
        # work is balanced across them.
        #
        # This configuration must be shared between all federation sender workers, and if
        # changed all federation sender workers must be stopped at the same time and then
        # started, to ensure that all instances are running with the same config (otherwise
        # events may be dropped).
        #
        #federation_sender_instances:
        #  - federation_sender1

        # When using workers this should be a map from `worker_name` to the
        # HTTP replication listener of the worker, if configured.
        #
        #instance_map:
        #  worker1:
        #    host: localhost
        #    port: 8034

        # Experimental: When using workers you can define which workers should
        # handle event persistence and typing notifications. Any worker
        # specified here must also be in the `instance_map`.
        #
        #stream_writers:
        #  events: worker1
        #  typing: worker1

        # The worker that is used to run background tasks (e.g. cleaning up expired
        # data). If not provided this defaults to the main process.
        #
        #run_background_tasks_on: worker1

        # A shared secret used by the replication APIs to authenticate HTTP requests
        # from workers.
        #
        # By default this is unused and traffic is not authenticated.
        #
        #worker_replication_secret: ""
        """

    def read_arguments(self, args):
        # We support a bunch of command line arguments that override options in
        # the config. A lot of these options have a worker_* prefix when running
        # on workers so we also have to override them when command line options
        # are specified.

        if args.daemonize is not None:
            self.worker_daemonize = args.daemonize
        if args.manhole is not None:
            self.worker_manhole = args.worker_manhole
