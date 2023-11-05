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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import attr

from synapse._pydantic_compat import HAS_PYDANTIC_V2

if TYPE_CHECKING or HAS_PYDANTIC_V2:
    from pydantic.v1 import BaseModel, Extra, StrictBool, StrictInt, StrictStr
else:
    from pydantic import BaseModel, Extra, StrictBool, StrictInt, StrictStr

from synapse.config._base import (
    Config,
    ConfigError,
    RoutableShardedWorkerHandlingConfig,
    ShardedWorkerHandlingConfig,
)
from synapse.config._util import parse_and_validate_mapping
from synapse.config.server import (
    DIRECT_TCP_ERROR,
    TCPListenerConfig,
    parse_listener_def,
)
from synapse.types import JsonDict

_DEPRECATED_WORKER_DUTY_OPTION_USED = """
The '%s' configuration option is deprecated and will be removed in a future
Synapse version. Please use ``%s: name_of_worker`` instead.
"""

_MISSING_MAIN_PROCESS_INSTANCE_MAP_DATA = """
Missing data for a worker to connect to main process. Please include '%s' in the
`instance_map` declared in your shared yaml configuration as defined in configuration
documentation here:
`https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#instance_map`
"""

WORKER_REPLICATION_SETTING_DEPRECATED_MESSAGE = """
'%s' is no longer a supported worker setting, please place '%s' onto your shared
configuration under `main` inside the `instance_map`. See workers documentation here:
`https://matrix-org.github.io/synapse/latest/workers.html#worker-configuration`
"""

# This allows for a handy knob when it's time to change from 'master' to
# something with less 'history'
MAIN_PROCESS_INSTANCE_NAME = "master"
# Use this to adjust what the main process is known as in the yaml instance_map
MAIN_PROCESS_INSTANCE_MAP_NAME = "main"

logger = logging.getLogger(__name__)


def _instance_to_list_converter(obj: Union[str, List[str]]) -> List[str]:
    """Helper for allowing parsing a string or list of strings to a config
    option expecting a list of strings.
    """

    if isinstance(obj, str):
        return [obj]
    return obj


class ConfigModel(BaseModel):
    """A custom version of Pydantic's BaseModel which

     - ignores unknown fields and
     - does not allow fields to be overwritten after construction,

    but otherwise uses Pydantic's default behaviour.

    For now, ignore unknown fields. In the future, we could change this so that unknown
    config values cause a ValidationError, provided the error messages are meaningful to
    server operators.

    Subclassing in this way is recommended by
    https://pydantic-docs.helpmanual.io/usage/model_config/#change-behaviour-globally
    """

    class Config:
        # By default, ignore fields that we don't recognise.
        extra = Extra.ignore
        # By default, don't allow fields to be reassigned after parsing.
        allow_mutation = False


class InstanceTcpLocationConfig(ConfigModel):
    """The host and port to talk to an instance via HTTP replication."""

    host: StrictStr
    port: StrictInt
    tls: StrictBool = False

    def scheme(self) -> str:
        """Hardcode a retrievable scheme based on self.tls"""
        return "https" if self.tls else "http"

    def netloc(self) -> str:
        """Nicely format the network location data"""
        return f"{self.host}:{self.port}"


class InstanceUnixLocationConfig(ConfigModel):
    """The socket file to talk to an instance via HTTP replication."""

    path: StrictStr

    def scheme(self) -> str:
        """Hardcode a retrievable scheme"""
        return "unix"

    def netloc(self) -> str:
        """Nicely format the address location data"""
        return f"{self.path}"


InstanceLocationConfig = Union[InstanceTcpLocationConfig, InstanceUnixLocationConfig]


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


@attr.s(auto_attribs=True)
class OutboundFederationRestrictedTo:
    """Whether we limit outbound federation to a certain set of instances.

    Attributes:
        instances: optional list of instances that can make outbound federation
            requests. If None then all instances can make federation requests.
        locations: list of instance locations to connect to proxy via.
    """

    instances: Optional[List[str]]
    locations: List[InstanceLocationConfig] = attr.Factory(list)

    def __contains__(self, instance: str) -> bool:
        # It feels a bit dirty to return `True` if `instances` is `None`, but it makes
        # sense in downstream usage in the sense that if
        # `outbound_federation_restricted_to` is not configured, then any instance can
        # talk to federation (no restrictions so always return `True`).
        return self.instances is None or instance in self.instances


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
            parse_listener_def(i, x)
            for i, x in enumerate(config.get("worker_listeners", []))
        ]
        self.worker_daemonize = bool(config.get("worker_daemonize"))
        self.worker_pid_file = config.get("worker_pid_file")

        worker_log_config = config.get("worker_log_config")
        if worker_log_config is not None and not isinstance(worker_log_config, str):
            raise ConfigError("worker_log_config must be a string")
        self.worker_log_config = worker_log_config

        # The port on the main synapse for TCP replication
        if "worker_replication_port" in config:
            raise ConfigError(DIRECT_TCP_ERROR, ("worker_replication_port",))

        # The shared secret used for authentication when connecting to the main synapse.
        self.worker_replication_secret = config.get("worker_replication_secret", None)

        self.worker_name = config.get("worker_name", self.worker_app)
        self.instance_name = self.worker_name or MAIN_PROCESS_INSTANCE_NAME

        # FIXME: Remove this check after a suitable amount of time.
        self.worker_main_http_uri = config.get("worker_main_http_uri", None)
        if self.worker_main_http_uri is not None:
            logger.warning(
                "The config option worker_main_http_uri is unused since Synapse 1.73. "
                "It can be safely removed from your configuration."
            )

        # This option is really only here to support `--manhole` command line
        # argument.
        manhole = config.get("worker_manhole")
        if manhole:
            self.worker_listeners.append(
                TCPListenerConfig(
                    port=manhole,
                    bind_addresses=["127.0.0.1"],
                    type="manhole",
                )
            )

        federation_sender_instances = self._worker_names_performing_this_duty(
            config,
            "send_federation",
            "synapse.app.federation_sender",
            "federation_sender_instances",
        )
        self.send_federation = self.instance_name in federation_sender_instances
        self.federation_shard_config = ShardedWorkerHandlingConfig(
            federation_sender_instances
        )

        # A map from instance name to host/port of their HTTP replication endpoint.
        # Check if the main process is declared. The main process itself doesn't need
        # this data as it would never have to talk to itself.
        instance_map: Dict[str, Any] = config.get("instance_map", {})

        if self.instance_name is not MAIN_PROCESS_INSTANCE_NAME:
            # TODO: The next 3 condition blocks can be deleted after some time has
            #  passed and we're ready to stop checking for these settings.
            # The host used to connect to the main synapse
            main_host = config.get("worker_replication_host", None)
            if main_host:
                raise ConfigError(
                    WORKER_REPLICATION_SETTING_DEPRECATED_MESSAGE
                    % ("worker_replication_host", main_host)
                )

            # The port on the main synapse for HTTP replication endpoint
            main_port = config.get("worker_replication_http_port")
            if main_port:
                raise ConfigError(
                    WORKER_REPLICATION_SETTING_DEPRECATED_MESSAGE
                    % ("worker_replication_http_port", main_port)
                )

            # The tls mode on the main synapse for HTTP replication endpoint.
            # For backward compatibility this defaults to False.
            main_tls = config.get("worker_replication_http_tls", False)
            if main_tls:
                raise ConfigError(
                    WORKER_REPLICATION_SETTING_DEPRECATED_MESSAGE
                    % ("worker_replication_http_tls", main_tls)
                )

            # For now, accept 'main' in the instance_map, but the replication system
            # expects 'master', force that into being until it's changed later.
            if MAIN_PROCESS_INSTANCE_MAP_NAME in instance_map:
                instance_map[MAIN_PROCESS_INSTANCE_NAME] = instance_map[
                    MAIN_PROCESS_INSTANCE_MAP_NAME
                ]
                del instance_map[MAIN_PROCESS_INSTANCE_MAP_NAME]

            else:
                # If we've gotten here, it means that the main process is not on the
                # instance_map.
                raise ConfigError(
                    _MISSING_MAIN_PROCESS_INSTANCE_MAP_DATA
                    % MAIN_PROCESS_INSTANCE_MAP_NAME
                )

        # type-ignore: the expression `Union[A, B]` is not a Type[Union[A, B]] currently
        self.instance_map: Dict[
            str, InstanceLocationConfig
        ] = parse_and_validate_mapping(
            instance_map, InstanceLocationConfig  # type: ignore[arg-type]
        )

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

        if len(self.writers.receipts) == 0:
            raise ConfigError(
                "Must specify at least one instance to handle `receipts` messages."
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
        pusher_instances = self._worker_names_performing_this_duty(
            config,
            "start_pushers",
            "synapse.app.pusher",
            "pusher_instances",
        )
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

        outbound_federation_restricted_to = config.get(
            "outbound_federation_restricted_to", None
        )
        self.outbound_federation_restricted_to = OutboundFederationRestrictedTo(
            outbound_federation_restricted_to
        )
        if outbound_federation_restricted_to:
            if not self.worker_replication_secret:
                raise ConfigError(
                    "`worker_replication_secret` must be configured when using `outbound_federation_restricted_to`."
                )

            for instance in outbound_federation_restricted_to:
                if instance not in self.instance_map:
                    raise ConfigError(
                        "Instance %r is configured in 'outbound_federation_restricted_to' but does not appear in `instance_map` config."
                        % (instance,)
                    )
                self.outbound_federation_restricted_to.locations.append(
                    self.instance_map[instance]
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

    def _worker_names_performing_this_duty(
        self,
        config: Dict[str, Any],
        legacy_option_name: str,
        legacy_app_name: str,
        modern_instance_list_name: str,
    ) -> List[str]:
        """
        Retrieves the names of the workers handling a given duty, by either legacy
        option or instance list.

        There are two ways of configuring which instances handle a given duty, e.g.
        for configuring pushers:

        1. The old way where "start_pushers" is set to false and running a
          `synapse.app.pusher'` worker app.
        2. Specifying the workers sending federation in `pusher_instances`.

        Args:
            config: settings read from yaml.
            legacy_option_name: the old way of enabling options. e.g. 'start_pushers'
            legacy_app_name: The historical app name. e.g. 'synapse.app.pusher'
            modern_instance_list_name: the string name of the new instance_list. e.g.
            'pusher_instances'

        Returns:
            A list of worker instance names handling the given duty.
        """

        legacy_option = config.get(legacy_option_name, True)

        worker_instances = config.get(modern_instance_list_name)
        if worker_instances is None:
            # Default to an empty list, which means "another, unknown, worker is
            # responsible for it".
            worker_instances = []

            # If no worker instances are set we check if the legacy option
            # is set, which means use the main process.
            if legacy_option:
                worker_instances = ["master"]

            if self.worker_app == legacy_app_name:
                if legacy_option:
                    # If we're using `legacy_app_name`, and not using
                    # `modern_instance_list_name`, then we should have
                    # explicitly set `legacy_option_name` to false.
                    raise ConfigError(
                        f"The '{legacy_option_name}' config option must be disabled in "
                        "the main synapse process before they can be run in a separate "
                        "worker.\n"
                        f"Please add `{legacy_option_name}: false` to the main config.\n",
                    )

                worker_instances = [self.worker_name]

        return worker_instances

    def read_arguments(self, args: argparse.Namespace) -> None:
        # We support a bunch of command line arguments that override options in
        # the config. A lot of these options have a worker_* prefix when running
        # on workers so we also have to override them when command line options
        # are specified.

        if args.daemonize is not None:
            self.worker_daemonize = args.daemonize
        if args.manhole is not None:
            self.worker_manhole = args.worker_manhole
