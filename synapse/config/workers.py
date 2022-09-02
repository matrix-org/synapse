# Copyright 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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

import argparse
import logging
from typing import Any, Dict, List, Union

import attr

from synapse.types import JsonDict

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

_DEPRECATED_WORKER_DUTY_OPTION_USED = """
The '%s' configuration option is deprecated and will be removed in a future
Synapse version. Please use ``%s: name_of_worker`` instead.
"""

logger = logging.getLogger(__name__)


def _instance_to_list_converter(obj: Union[str, List[str]]) -> List[str]:
    """Helper for allowing parsing a string or list of strings to a config
    option expecting a list of strings.
    """

    if isinstance(obj, str):
        return [obj]
    return obj


@attr.s(auto_attribs=True)
class InstanceLocationConfig:
    """The host and port to talk to an instance via HTTP replication."""

    host: str
    port: int


@attr.s
class WriterLocations:
    """Specifies the instances that write various streams.

    Attributes:
        events: The instances that write to the event and backfill streams.
        typing: The instances that write to the typing stream. Currently
            can only be a single instance.
        to_device: The instances that write to the to_device stream. Currently
            can only be a single instance.
        account_data: The instances that write to the account data streams. Currently
            can only be a single instance.
        receipts: The instances that write to the receipts stream. Currently
            can only be a single instance.
        presence: The instances that write to the presence stream. Currently
            can only be a single instance.
    """

    events: List[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    typing: List[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    to_device: List[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    account_data: List[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    receipts: List[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    presence: List[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )


class WorkerConfig(Config):
    """The workers are processes run separately to the main synapse process.
    They have their own pid_file and listener configuration. They use the
    replication_url to talk to the main synapse process."""

    section = "worker"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.worker_app = config.get("worker_app")

        # Canonicalise worker_app so that master always has None
        if self.worker_app == "synapse.app.homeserver":
            self.worker_app = None

        self.worker_listeners = [
            parse_listener_def(x) for x in config.get("worker_listeners", [])
        ]
        self.worker_daemonize = bool(config.get("worker_daemonize"))
        self.worker_pid_file = config.get("worker_pid_file")

        worker_log_config = config.get("worker_log_config")
        if worker_log_config is not None and not isinstance(worker_log_config, str):
            raise ConfigError("worker_log_config must be a string")
        self.worker_log_config = worker_log_config

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

        if len(self.writers.typing) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `typing` messages."
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

        self.should_notify_appservices = self._should_this_worker_perform_duty(
            config,
            legacy_master_option_name="notify_appservices",
            legacy_worker_app_name="synapse.app.appservice",
            new_option_name="notify_appservices_from_worker",
        )

        self.should_update_user_directory = self._should_this_worker_perform_duty(
            config,
            legacy_master_option_name="update_user_directory",
            legacy_worker_app_name="synapse.app.user_dir",
            new_option_name="update_user_directory_from_worker",
        )

    def _should_this_worker_perform_duty(
        self,
        config: Dict[str, Any],
        legacy_master_option_name: str,
        legacy_worker_app_name: str,
        new_option_name: str,
    ) -> bool:
        """
        Figures out whether this worker should perform a certain duty.

        This function is temporary and is only to deal with the complexity
        of allowing old, transitional and new configurations all at once.

        Contradictions between the legacy and new part of a transitional configuration
        will lead to a ConfigError.

        Parameters:
            config: The config dictionary
            legacy_master_option_name: The name of a legacy option, whose value is boolean,
                specifying whether it's the master that should handle a certain duty.
                e.g. "notify_appservices"
            legacy_worker_app_name: The name of a legacy Synapse worker application
                that would traditionally perform this duty.
                e.g. "synapse.app.appservice"
            new_option_name: The name of the new option, whose value is the name of a
                designated worker to perform the duty.
                e.g. "notify_appservices_from_worker"
        """

        # None means 'unspecified'; True means 'run here' and False means
        # 'don't run here'.
        new_option_should_run_here = None
        if new_option_name in config:
            designated_worker = config[new_option_name] or "master"
            new_option_should_run_here = (
                designated_worker == "master" and self.worker_name is None
            ) or designated_worker == self.worker_name

        legacy_option_should_run_here = None
        if legacy_master_option_name in config:
            run_on_master = bool(config[legacy_master_option_name])

            legacy_option_should_run_here = (
                self.worker_name is None and run_on_master
            ) or (self.worker_app == legacy_worker_app_name and not run_on_master)

            # Suggest using the new option instead.
            logger.warning(
                _DEPRECATED_WORKER_DUTY_OPTION_USED,
                legacy_master_option_name,
                new_option_name,
            )

        if self.worker_app == legacy_worker_app_name and config.get(
            legacy_master_option_name, True
        ):
            # As an extra bit of complication, we need to check that the
            # specialised worker is only used if the legacy config says the
            # master isn't performing the duties.
            raise ConfigError(
                f"Cannot use deprecated worker app type '{legacy_worker_app_name}' whilst deprecated option '{legacy_master_option_name}' is not set to false.\n"
                f"Consider setting `worker_app: synapse.app.generic_worker` and using the '{new_option_name}' option instead.\n"
                f"The '{new_option_name}' option replaces '{legacy_master_option_name}'."
            )

        if new_option_should_run_here is None and legacy_option_should_run_here is None:
            # Neither option specified; the fallback behaviour is to run on the main process
            return self.worker_name is None

        if (
            new_option_should_run_here is not None
            and legacy_option_should_run_here is not None
        ):
            # Both options specified; ensure they match!
            if new_option_should_run_here != legacy_option_should_run_here:
                update_worker_type = (
                    " and set worker_app: synapse.app.generic_worker"
                    if self.worker_app == legacy_worker_app_name
                    else ""
                )
                # If the values conflict, we suggest the admin removes the legacy option
                # for simplicity.
                raise ConfigError(
                    f"Conflicting configuration options: {legacy_master_option_name} (legacy), {new_option_name} (new).\n"
                    f"Suggestion: remove {legacy_master_option_name}{update_worker_type}.\n"
                )

        # We've already validated that these aren't conflicting; now just see if
        # either is True.
        # (By this point, these are either the same value or only one is not None.)
        return bool(new_option_should_run_here or legacy_option_should_run_here)

    def read_arguments(self, args: argparse.Namespace) -> None:
        # We support a bunch of command line arguments that override options in
        # the config. A lot of these options have a worker_* prefix when running
        # on workers so we also have to override them when command line options
        # are specified.

        if args.daemonize is not None:
            self.worker_daemonize = args.daemonize
        if args.manhole is not None:
            self.worker_manhole = args.worker_manhole
