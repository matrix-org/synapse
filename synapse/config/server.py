# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import os.path
import re
from textwrap import indent
from typing import Any, Dict, Iterable, List, Optional, Set

import attr
import yaml

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.http.endpoint import parse_and_validate_server_name

from ._base import Config, ConfigError

logger = logging.Logger(__name__)

# by default, we attempt to listen on both '::' *and* '0.0.0.0' because some OSes
# (Windows, macOS, other BSD/Linux where net.ipv6.bindv6only is set) will only listen
# on IPv6 when '::' is set.
#
# We later check for errors when binding to 0.0.0.0 and ignore them if :: is also in
# in the list.
DEFAULT_BIND_ADDRESSES = ["::", "0.0.0.0"]

DEFAULT_ROOM_VERSION = "5"

ROOM_COMPLEXITY_TOO_GREAT = (
    "Your homeserver is unable to join rooms this large or complex. "
    "Please speak to your server administrator, or upgrade your instance "
    "to join this room."
)

METRICS_PORT_WARNING = """\
The metrics_port configuration option is deprecated in Synapse 0.31 in favour of
a listener. Please see
https://github.com/matrix-org/synapse/blob/master/docs/metrics-howto.md
on how to configure the new listener.
--------------------------------------------------------------------------------"""


KNOWN_LISTENER_TYPES = {
    "http",
    "metrics",
    "manhole",
    "replication",
}

KNOWN_RESOURCES = {
    "client",
    "consent",
    "federation",
    "keys",
    "media",
    "metrics",
    "openid",
    "replication",
    "static",
    "webclient",
}


@attr.s(frozen=True)
class HttpResourceConfig:
    names = attr.ib(
        type=List[str],
        factory=list,
        validator=attr.validators.deep_iterable(attr.validators.in_(KNOWN_RESOURCES)),  # type: ignore
    )
    compress = attr.ib(
        type=bool,
        default=False,
        validator=attr.validators.optional(attr.validators.instance_of(bool)),  # type: ignore[arg-type]
    )


@attr.s(frozen=True)
class HttpListenerConfig:
    """Object describing the http-specific parts of the config of a listener"""

    x_forwarded = attr.ib(type=bool, default=False)
    resources = attr.ib(type=List[HttpResourceConfig], factory=list)
    additional_resources = attr.ib(type=Dict[str, dict], factory=dict)
    tag = attr.ib(type=str, default=None)


@attr.s(frozen=True)
class ListenerConfig:
    """Object describing the configuration of a single listener."""

    port = attr.ib(type=int, validator=attr.validators.instance_of(int))
    bind_addresses = attr.ib(type=List[str])
    type = attr.ib(type=str, validator=attr.validators.in_(KNOWN_LISTENER_TYPES))
    tls = attr.ib(type=bool, default=False)

    # http_options is only populated if type=http
    http_options = attr.ib(type=Optional[HttpListenerConfig], default=None)


class ServerConfig(Config):
    section = "server"

    def read_config(self, config, **kwargs):
        self.server_name = config["server_name"]
        self.server_context = config.get("server_context", None)

        try:
            parse_and_validate_server_name(self.server_name)
        except ValueError as e:
            raise ConfigError(str(e))

        self.pid_file = self.abspath(config.get("pid_file"))
        self.web_client_location = config.get("web_client_location", None)
        self.soft_file_limit = config.get("soft_file_limit", 0)
        self.daemonize = config.get("daemonize")
        self.print_pidfile = config.get("print_pidfile")
        self.user_agent_suffix = config.get("user_agent_suffix")
        self.use_frozen_dicts = config.get("use_frozen_dicts", False)
        self.public_baseurl = config.get("public_baseurl")

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

        # Whether to require authentication to retrieve profile data (avatars,
        # display names) of other users through the client API.
        self.require_auth_for_profile_requests = config.get(
            "require_auth_for_profile_requests", False
        )

        # Whether to require sharing a room with a user to retrieve their
        # profile data
        self.limit_profile_requests_to_users_who_share_rooms = config.get(
            "limit_profile_requests_to_users_who_share_rooms", False,
        )

        if "restrict_public_rooms_to_local_users" in config and (
            "allow_public_rooms_without_auth" in config
            or "allow_public_rooms_over_federation" in config
        ):
            raise ConfigError(
                "Can't use 'restrict_public_rooms_to_local_users' if"
                " 'allow_public_rooms_without_auth' and/or"
                " 'allow_public_rooms_over_federation' is set."
            )

        # Check if the legacy "restrict_public_rooms_to_local_users" flag is set. This
        # flag is now obsolete but we need to check it for backward-compatibility.
        if config.get("restrict_public_rooms_to_local_users", False):
            self.allow_public_rooms_without_auth = False
            self.allow_public_rooms_over_federation = False
        else:
            # If set to 'true', removes the need for authentication to access the server's
            # public rooms directory through the client API, meaning that anyone can
            # query the room directory. Defaults to 'false'.
            self.allow_public_rooms_without_auth = config.get(
                "allow_public_rooms_without_auth", False
            )
            # If set to 'true', allows any other homeserver to fetch the server's public
            # rooms directory via federation. Defaults to 'false'.
            self.allow_public_rooms_over_federation = config.get(
                "allow_public_rooms_over_federation", False
            )

        default_room_version = config.get("default_room_version", DEFAULT_ROOM_VERSION)

        # Ensure room version is a str
        default_room_version = str(default_room_version)

        if default_room_version not in KNOWN_ROOM_VERSIONS:
            raise ConfigError(
                "Unknown default_room_version: %s, known room versions: %s"
                % (default_room_version, list(KNOWN_ROOM_VERSIONS.keys()))
            )

        # Get the actual room version object rather than just the identifier
        self.default_room_version = KNOWN_ROOM_VERSIONS[default_room_version]

        # whether to enable search. If disabled, new entries will not be inserted
        # into the search tables and they will not be indexed. Users will receive
        # errors when attempting to search for messages.
        self.enable_search = config.get("enable_search", True)

        self.filter_timeline_limit = config.get("filter_timeline_limit", 100)

        # Whether we should block invites sent to users on this server
        # (other than those sent by local server admins)
        self.block_non_admin_invites = config.get("block_non_admin_invites", False)

        # Whether to enable experimental MSC1849 (aka relations) support
        self.experimental_msc1849_support_enabled = config.get(
            "experimental_msc1849_support_enabled", True
        )

        # Options to control access by tracking MAU
        self.limit_usage_by_mau = config.get("limit_usage_by_mau", False)
        self.max_mau_value = 0
        if self.limit_usage_by_mau:
            self.max_mau_value = config.get("max_mau_value", 0)
        self.mau_stats_only = config.get("mau_stats_only", False)

        self.mau_limits_reserved_threepids = config.get(
            "mau_limit_reserved_threepids", []
        )

        self.mau_trial_days = config.get("mau_trial_days", 0)
        self.mau_limit_alerting = config.get("mau_limit_alerting", True)

        # How long to keep redacted events in the database in unredacted form
        # before redacting them.
        redaction_retention_period = config.get("redaction_retention_period", "7d")
        if redaction_retention_period is not None:
            self.redaction_retention_period = self.parse_duration(
                redaction_retention_period
            )
        else:
            self.redaction_retention_period = None

        # How long to keep entries in the `users_ips` table.
        user_ips_max_age = config.get("user_ips_max_age", "28d")
        if user_ips_max_age is not None:
            self.user_ips_max_age = self.parse_duration(user_ips_max_age)
        else:
            self.user_ips_max_age = None

        # Options to disable HS
        self.hs_disabled = config.get("hs_disabled", False)
        self.hs_disabled_message = config.get("hs_disabled_message", "")

        # Admin uri to direct users at should their instance become blocked
        # due to resource constraints
        self.admin_contact = config.get("admin_contact", None)

        if self.public_baseurl is not None:
            if self.public_baseurl[-1] != "/":
                self.public_baseurl += "/"
        self.start_pushers = config.get("start_pushers", True)

        # (undocumented) option for torturing the worker-mode replication a bit,
        # for testing. The value defines the number of milliseconds to pause before
        # sending out any replication updates.
        self.replication_torture_level = config.get("replication_torture_level")

        # Whether to require a user to be in the room to add an alias to it.
        # Defaults to True.
        self.require_membership_for_aliases = config.get(
            "require_membership_for_aliases", True
        )

        # Whether to allow per-room membership profiles through the send of membership
        # events with profile information that differ from the target's global profile.
        self.allow_per_room_profiles = config.get("allow_per_room_profiles", True)

        retention_config = config.get("retention")
        if retention_config is None:
            retention_config = {}

        self.retention_enabled = retention_config.get("enabled", False)

        retention_default_policy = retention_config.get("default_policy")

        if retention_default_policy is not None:
            self.retention_default_min_lifetime = retention_default_policy.get(
                "min_lifetime"
            )
            if self.retention_default_min_lifetime is not None:
                self.retention_default_min_lifetime = self.parse_duration(
                    self.retention_default_min_lifetime
                )

            self.retention_default_max_lifetime = retention_default_policy.get(
                "max_lifetime"
            )
            if self.retention_default_max_lifetime is not None:
                self.retention_default_max_lifetime = self.parse_duration(
                    self.retention_default_max_lifetime
                )

            if (
                self.retention_default_min_lifetime is not None
                and self.retention_default_max_lifetime is not None
                and (
                    self.retention_default_min_lifetime
                    > self.retention_default_max_lifetime
                )
            ):
                raise ConfigError(
                    "The default retention policy's 'min_lifetime' can not be greater"
                    " than its 'max_lifetime'"
                )
        else:
            self.retention_default_min_lifetime = None
            self.retention_default_max_lifetime = None

        if self.retention_enabled:
            logger.info(
                "Message retention policies support enabled with the following default"
                " policy: min_lifetime = %s ; max_lifetime = %s",
                self.retention_default_min_lifetime,
                self.retention_default_max_lifetime,
            )

        self.retention_allowed_lifetime_min = retention_config.get(
            "allowed_lifetime_min"
        )
        if self.retention_allowed_lifetime_min is not None:
            self.retention_allowed_lifetime_min = self.parse_duration(
                self.retention_allowed_lifetime_min
            )

        self.retention_allowed_lifetime_max = retention_config.get(
            "allowed_lifetime_max"
        )
        if self.retention_allowed_lifetime_max is not None:
            self.retention_allowed_lifetime_max = self.parse_duration(
                self.retention_allowed_lifetime_max
            )

        if (
            self.retention_allowed_lifetime_min is not None
            and self.retention_allowed_lifetime_max is not None
            and self.retention_allowed_lifetime_min
            > self.retention_allowed_lifetime_max
        ):
            raise ConfigError(
                "Invalid retention policy limits: 'allowed_lifetime_min' can not be"
                " greater than 'allowed_lifetime_max'"
            )

        self.retention_purge_jobs = []  # type: List[Dict[str, Optional[int]]]
        for purge_job_config in retention_config.get("purge_jobs", []):
            interval_config = purge_job_config.get("interval")

            if interval_config is None:
                raise ConfigError(
                    "A retention policy's purge jobs configuration must have the"
                    " 'interval' key set."
                )

            interval = self.parse_duration(interval_config)

            shortest_max_lifetime = purge_job_config.get("shortest_max_lifetime")

            if shortest_max_lifetime is not None:
                shortest_max_lifetime = self.parse_duration(shortest_max_lifetime)

            longest_max_lifetime = purge_job_config.get("longest_max_lifetime")

            if longest_max_lifetime is not None:
                longest_max_lifetime = self.parse_duration(longest_max_lifetime)

            if (
                shortest_max_lifetime is not None
                and longest_max_lifetime is not None
                and shortest_max_lifetime > longest_max_lifetime
            ):
                raise ConfigError(
                    "A retention policy's purge jobs configuration's"
                    " 'shortest_max_lifetime' value can not be greater than its"
                    " 'longest_max_lifetime' value."
                )

            self.retention_purge_jobs.append(
                {
                    "interval": interval,
                    "shortest_max_lifetime": shortest_max_lifetime,
                    "longest_max_lifetime": longest_max_lifetime,
                }
            )

        if not self.retention_purge_jobs:
            self.retention_purge_jobs = [
                {
                    "interval": self.parse_duration("1d"),
                    "shortest_max_lifetime": None,
                    "longest_max_lifetime": None,
                }
            ]

        self.listeners = [parse_listener_def(x) for x in config.get("listeners", [])]

        # no_tls is not really supported any more, but let's grandfather it in
        # here.
        if config.get("no_tls", False):
            l2 = []
            for listener in self.listeners:
                if listener.tls:
                    logger.info(
                        "Ignoring TLS-enabled listener on port %i due to no_tls",
                        listener.port,
                    )
                else:
                    l2.append(listener)
            self.listeners = l2

        if not self.web_client_location:
            _warn_if_webclient_configured(self.listeners)

        self.gc_thresholds = read_gc_thresholds(config.get("gc_thresholds", None))

        @attr.s
        class LimitRemoteRoomsConfig:
            enabled = attr.ib(
                validator=attr.validators.instance_of(bool), default=False
            )
            complexity = attr.ib(
                validator=attr.validators.instance_of(
                    (float, int)  # type: ignore[arg-type] # noqa
                ),
                default=1.0,
            )
            complexity_error = attr.ib(
                validator=attr.validators.instance_of(str),
                default=ROOM_COMPLEXITY_TOO_GREAT,
            )
            admins_can_join = attr.ib(
                validator=attr.validators.instance_of(bool), default=False
            )

        self.limit_remote_rooms = LimitRemoteRoomsConfig(
            **(config.get("limit_remote_rooms") or {})
        )

        bind_port = config.get("bind_port")
        if bind_port:
            if config.get("no_tls", False):
                raise ConfigError("no_tls is incompatible with bind_port")

            self.listeners = []
            bind_host = config.get("bind_host", "")
            gzip_responses = config.get("gzip_responses", True)

            http_options = HttpListenerConfig(
                resources=[
                    HttpResourceConfig(names=["client"], compress=gzip_responses),
                    HttpResourceConfig(names=["federation"]),
                ],
            )

            self.listeners.append(
                ListenerConfig(
                    port=bind_port,
                    bind_addresses=[bind_host],
                    tls=True,
                    type="http",
                    http_options=http_options,
                )
            )

            unsecure_port = config.get("unsecure_port", bind_port - 400)
            if unsecure_port:
                self.listeners.append(
                    ListenerConfig(
                        port=unsecure_port,
                        bind_addresses=[bind_host],
                        tls=False,
                        type="http",
                        http_options=http_options,
                    )
                )

        manhole = config.get("manhole")
        if manhole:
            self.listeners.append(
                ListenerConfig(
                    port=manhole, bind_addresses=["127.0.0.1"], type="manhole",
                )
            )

        metrics_port = config.get("metrics_port")
        if metrics_port:
            logger.warning(METRICS_PORT_WARNING)

            self.listeners.append(
                ListenerConfig(
                    port=metrics_port,
                    bind_addresses=[config.get("metrics_bind_host", "127.0.0.1")],
                    type="http",
                    http_options=HttpListenerConfig(
                        resources=[HttpResourceConfig(names=["metrics"])]
                    ),
                )
            )

        self.cleanup_extremities_with_dummy_events = config.get(
            "cleanup_extremities_with_dummy_events", True
        )

        # The number of forward extremities in a room needed to send a dummy event.
        self.dummy_events_threshold = config.get("dummy_events_threshold", 10)

        self.enable_ephemeral_messages = config.get("enable_ephemeral_messages", False)

        # Inhibits the /requestToken endpoints from returning an error that might leak
        # information about whether an e-mail address is in use or not on this
        # homeserver, and instead return a 200 with a fake sid if this kind of error is
        # met, without sending anything.
        # This is a compromise between sending an email, which could be a spam vector,
        # and letting the client know which email address is bound to an account and
        # which one isn't.
        self.request_token_inhibit_3pid_errors = config.get(
            "request_token_inhibit_3pid_errors", False,
        )

        # List of users trialing the new experimental default push rules. This setting is
        # not included in the sample configuration file on purpose as it's a temporary
        # hack, so that some users can trial the new defaults without impacting every
        # user on the homeserver.
        users_new_default_push_rules = (
            config.get("users_new_default_push_rules") or []
        )  # type: list
        if not isinstance(users_new_default_push_rules, list):
            raise ConfigError("'users_new_default_push_rules' must be a list")

        # Turn the list into a set to improve lookup speed.
        self.users_new_default_push_rules = set(
            users_new_default_push_rules
        )  # type: set

        # Whitelist of domain names that given next_link parameters must have
        next_link_domain_whitelist = config.get(
            "next_link_domain_whitelist"
        )  # type: Optional[List[str]]

        self.next_link_domain_whitelist = None  # type: Optional[Set[str]]
        if next_link_domain_whitelist is not None:
            if not isinstance(next_link_domain_whitelist, list):
                raise ConfigError("'next_link_domain_whitelist' must be a list")

            # Turn the list into a set to improve lookup speed.
            self.next_link_domain_whitelist = set(next_link_domain_whitelist)

    def has_tls_listener(self) -> bool:
        return any(listener.tls for listener in self.listeners)

    def generate_config_section(
        self, server_name, data_dir_path, open_private_ports, listeners, **kwargs
    ):
        _, bind_port = parse_and_validate_server_name(server_name)
        if bind_port is not None:
            unsecure_port = bind_port - 400
        else:
            bind_port = 8448
            unsecure_port = 8008

        pid_file = os.path.join(data_dir_path, "homeserver.pid")

        # Bring DEFAULT_ROOM_VERSION into the local-scope for use in the
        # default config string
        default_room_version = DEFAULT_ROOM_VERSION
        secure_listeners = []
        unsecure_listeners = []
        private_addresses = ["::1", "127.0.0.1"]
        if listeners:
            for listener in listeners:
                if listener["tls"]:
                    secure_listeners.append(listener)
                else:
                    # If we don't want open ports we need to bind the listeners
                    # to some address other than 0.0.0.0. Here we chose to use
                    # localhost.
                    # If the addresses are already bound we won't overwrite them
                    # however.
                    if not open_private_ports:
                        listener.setdefault("bind_addresses", private_addresses)

                    unsecure_listeners.append(listener)

            secure_http_bindings = indent(
                yaml.dump(secure_listeners), " " * 10
            ).lstrip()

            unsecure_http_bindings = indent(
                yaml.dump(unsecure_listeners), " " * 10
            ).lstrip()

        if not unsecure_listeners:
            unsecure_http_bindings = (
                """- port: %(unsecure_port)s
            tls: false
            type: http
            x_forwarded: true"""
                % locals()
            )

            if not open_private_ports:
                unsecure_http_bindings += (
                    "\n            bind_addresses: ['::1', '127.0.0.1']"
                )

            unsecure_http_bindings += """

            resources:
              - names: [client, federation]
                compress: false"""

            if listeners:
                # comment out this block
                unsecure_http_bindings = "#" + re.sub(
                    "\n {10}",
                    lambda match: match.group(0) + "#",
                    unsecure_http_bindings,
                )

        if not secure_listeners:
            secure_http_bindings = (
                """#- port: %(bind_port)s
          #  type: http
          #  tls: true
          #  resources:
          #    - names: [client, federation]"""
                % locals()
            )

        return (
            """\
        ## Server ##

        # The public-facing domain of the server
        #
        # The server_name name will appear at the end of usernames and room addresses
        # created on this server. For example if the server_name was example.com,
        # usernames on this server would be in the format @user:example.com
        #
        # In most cases you should avoid using a matrix specific subdomain such as
        # matrix.example.com or synapse.example.com as the server_name for the same
        # reasons you wouldn't use user@email.example.com as your email address.
        # See https://github.com/matrix-org/synapse/blob/master/docs/delegate.md
        # for information on how to host Synapse on a subdomain while preserving
        # a clean server_name.
        #
        # The server_name cannot be changed later so it is important to
        # configure this correctly before you start Synapse. It should be all
        # lowercase and may contain an explicit port.
        # Examples: matrix.org, localhost:8080
        #
        server_name: "%(server_name)s"

        # When running as a daemon, the file to store the pid in
        #
        pid_file: %(pid_file)s

        # The absolute URL to the web client which /_matrix/client will redirect
        # to if 'webclient' is configured under the 'listeners' configuration.
        #
        # This option can be also set to the filesystem path to the web client
        # which will be served at /_matrix/client/ if 'webclient' is configured
        # under the 'listeners' configuration, however this is a security risk:
        # https://github.com/matrix-org/synapse#security-note
        #
        #web_client_location: https://riot.example.com/

        # The public-facing base URL that clients use to access this HS
        # (not including _matrix/...). This is the same URL a user would
        # enter into the 'custom HS URL' field on their client. If you
        # use synapse with a reverse proxy, this should be the URL to reach
        # synapse via the proxy.
        #
        #public_baseurl: https://example.com/

        # Set the soft limit on the number of file descriptors synapse can use
        # Zero is used to indicate synapse should set the soft limit to the
        # hard limit.
        #
        #soft_file_limit: 0

        # Set to false to disable presence tracking on this homeserver.
        #
        #use_presence: false

        # Whether to require authentication to retrieve profile data (avatars,
        # display names) of other users through the client API. Defaults to
        # 'false'. Note that profile data is also available via the federation
        # API, so this setting is of limited value if federation is enabled on
        # the server.
        #
        #require_auth_for_profile_requests: true

        # Uncomment to require a user to share a room with another user in order
        # to retrieve their profile information. Only checked on Client-Server
        # requests. Profile requests from other servers should be checked by the
        # requesting server. Defaults to 'false'.
        #
        #limit_profile_requests_to_users_who_share_rooms: true

        # If set to 'true', removes the need for authentication to access the server's
        # public rooms directory through the client API, meaning that anyone can
        # query the room directory. Defaults to 'false'.
        #
        #allow_public_rooms_without_auth: true

        # If set to 'true', allows any other homeserver to fetch the server's public
        # rooms directory via federation. Defaults to 'false'.
        #
        #allow_public_rooms_over_federation: true

        # The default room version for newly created rooms.
        #
        # Known room versions are listed here:
        # https://matrix.org/docs/spec/#complete-list-of-room-versions
        #
        # For example, for room version 1, default_room_version should be set
        # to "1".
        #
        #default_room_version: "%(default_room_version)s"

        # The GC threshold parameters to pass to `gc.set_threshold`, if defined
        #
        #gc_thresholds: [700, 10, 10]

        # Set the limit on the returned events in the timeline in the get
        # and sync operations. The default value is 100. -1 means no upper limit.
        #
        # Uncomment the following to increase the limit to 5000.
        #
        #filter_timeline_limit: 5000

        # Whether room invites to users on this server should be blocked
        # (except those sent by local server admins). The default is False.
        #
        #block_non_admin_invites: true

        # Room searching
        #
        # If disabled, new messages will not be indexed for searching and users
        # will receive errors when searching for messages. Defaults to enabled.
        #
        #enable_search: false

        # List of ports that Synapse should listen on, their purpose and their
        # configuration.
        #
        # Options for each listener include:
        #
        #   port: the TCP port to bind to
        #
        #   bind_addresses: a list of local addresses to listen on. The default is
        #       'all local interfaces'.
        #
        #   type: the type of listener. Normally 'http', but other valid options are:
        #       'manhole' (see docs/manhole.md),
        #       'metrics' (see docs/metrics-howto.md),
        #       'replication' (see docs/workers.md).
        #
        #   tls: set to true to enable TLS for this listener. Will use the TLS
        #       key/cert specified in tls_private_key_path / tls_certificate_path.
        #
        #   x_forwarded: Only valid for an 'http' listener. Set to true to use the
        #       X-Forwarded-For header as the client IP. Useful when Synapse is
        #       behind a reverse-proxy.
        #
        #   resources: Only valid for an 'http' listener. A list of resources to host
        #       on this port. Options for each resource are:
        #
        #       names: a list of names of HTTP resources. See below for a list of
        #           valid resource names.
        #
        #       compress: set to true to enable HTTP compression for this resource.
        #
        #   additional_resources: Only valid for an 'http' listener. A map of
        #        additional endpoints which should be loaded via dynamic modules.
        #
        # Valid resource names are:
        #
        #   client: the client-server API (/_matrix/client), and the synapse admin
        #       API (/_synapse/admin). Also implies 'media' and 'static'.
        #
        #   consent: user consent forms (/_matrix/consent). See
        #       docs/consent_tracking.md.
        #
        #   federation: the server-server API (/_matrix/federation). Also implies
        #       'media', 'keys', 'openid'
        #
        #   keys: the key discovery API (/_matrix/keys).
        #
        #   media: the media API (/_matrix/media).
        #
        #   metrics: the metrics interface. See docs/metrics-howto.md.
        #
        #   openid: OpenID authentication.
        #
        #   replication: the HTTP replication API (/_synapse/replication). See
        #       docs/workers.md.
        #
        #   static: static resources under synapse/static (/_matrix/static). (Mostly
        #       useful for 'fallback authentication'.)
        #
        #   webclient: A web client. Requires web_client_location to be set.
        #
        listeners:
          # TLS-enabled listener: for when matrix traffic is sent directly to synapse.
          #
          # Disabled by default. To enable it, uncomment the following. (Note that you
          # will also need to give Synapse a TLS key and certificate: see the TLS section
          # below.)
          #
          %(secure_http_bindings)s

          # Unsecure HTTP listener: for when matrix traffic passes through a reverse proxy
          # that unwraps TLS.
          #
          # If you plan to use a reverse proxy, please see
          # https://github.com/matrix-org/synapse/blob/master/docs/reverse_proxy.md.
          #
          %(unsecure_http_bindings)s

            # example additional_resources:
            #
            #additional_resources:
            #  "/_matrix/my/custom/endpoint":
            #    module: my_module.CustomRequestHandler
            #    config: {}

          # Turn on the twisted ssh manhole service on localhost on the given
          # port.
          #
          #- port: 9000
          #  bind_addresses: ['::1', '127.0.0.1']
          #  type: manhole

        # Forward extremities can build up in a room due to networking delays between
        # homeservers. Once this happens in a large room, calculation of the state of
        # that room can become quite expensive. To mitigate this, once the number of
        # forward extremities reaches a given threshold, Synapse will send an
        # org.matrix.dummy_event event, which will reduce the forward extremities
        # in the room.
        #
        # This setting defines the threshold (i.e. number of forward extremities in the
        # room) at which dummy events are sent. The default value is 10.
        #
        #dummy_events_threshold: 5


        ## Homeserver blocking ##

        # How to reach the server admin, used in ResourceLimitError
        #
        #admin_contact: 'mailto:admin@server.com'

        # Global blocking
        #
        #hs_disabled: false
        #hs_disabled_message: 'Human readable reason for why the HS is blocked'

        # Monthly Active User Blocking
        #
        # Used in cases where the admin or server owner wants to limit to the
        # number of monthly active users.
        #
        # 'limit_usage_by_mau' disables/enables monthly active user blocking. When
        # enabled and a limit is reached the server returns a 'ResourceLimitError'
        # with error type Codes.RESOURCE_LIMIT_EXCEEDED
        #
        # 'max_mau_value' is the hard limit of monthly active users above which
        # the server will start blocking user actions.
        #
        # 'mau_trial_days' is a means to add a grace period for active users. It
        # means that users must be active for this number of days before they
        # can be considered active and guards against the case where lots of users
        # sign up in a short space of time never to return after their initial
        # session.
        #
        # 'mau_limit_alerting' is a means of limiting client side alerting
        # should the mau limit be reached. This is useful for small instances
        # where the admin has 5 mau seats (say) for 5 specific people and no
        # interest increasing the mau limit further. Defaults to True, which
        # means that alerting is enabled
        #
        #limit_usage_by_mau: false
        #max_mau_value: 50
        #mau_trial_days: 2
        #mau_limit_alerting: false

        # If enabled, the metrics for the number of monthly active users will
        # be populated, however no one will be limited. If limit_usage_by_mau
        # is true, this is implied to be true.
        #
        #mau_stats_only: false

        # Sometimes the server admin will want to ensure certain accounts are
        # never blocked by mau checking. These accounts are specified here.
        #
        #mau_limit_reserved_threepids:
        #  - medium: 'email'
        #    address: 'reserved_user@example.com'

        # Used by phonehome stats to group together related servers.
        #server_context: context

        # Resource-constrained homeserver settings
        #
        # When this is enabled, the room "complexity" will be checked before a user
        # joins a new remote room. If it is above the complexity limit, the server will
        # disallow joining, or will instantly leave.
        #
        # Room complexity is an arbitrary measure based on factors such as the number of
        # users in the room.
        #
        limit_remote_rooms:
          # Uncomment to enable room complexity checking.
          #
          #enabled: true

          # the limit above which rooms cannot be joined. The default is 1.0.
          #
          #complexity: 0.5

          # override the error which is returned when the room is too complex.
          #
          #complexity_error: "This room is too complex."

          # allow server admins to join complex rooms. Default is false.
          #
          #admins_can_join: true

        # Whether to require a user to be in the room to add an alias to it.
        # Defaults to 'true'.
        #
        #require_membership_for_aliases: false

        # Whether to allow per-room membership profiles through the send of membership
        # events with profile information that differ from the target's global profile.
        # Defaults to 'true'.
        #
        #allow_per_room_profiles: false

        # How long to keep redacted events in unredacted form in the database. After
        # this period redacted events get replaced with their redacted form in the DB.
        #
        # Defaults to `7d`. Set to `null` to disable.
        #
        #redaction_retention_period: 28d

        # How long to track users' last seen time and IPs in the database.
        #
        # Defaults to `28d`. Set to `null` to disable clearing out of old rows.
        #
        #user_ips_max_age: 14d

        # Message retention policy at the server level.
        #
        # Room admins and mods can define a retention period for their rooms using the
        # 'm.room.retention' state event, and server admins can cap this period by setting
        # the 'allowed_lifetime_min' and 'allowed_lifetime_max' config options.
        #
        # If this feature is enabled, Synapse will regularly look for and purge events
        # which are older than the room's maximum retention period. Synapse will also
        # filter events received over federation so that events that should have been
        # purged are ignored and not stored again.
        #
        retention:
          # The message retention policies feature is disabled by default. Uncomment the
          # following line to enable it.
          #
          #enabled: true

          # Default retention policy. If set, Synapse will apply it to rooms that lack the
          # 'm.room.retention' state event. Currently, the value of 'min_lifetime' doesn't
          # matter much because Synapse doesn't take it into account yet.
          #
          #default_policy:
          #  min_lifetime: 1d
          #  max_lifetime: 1y

          # Retention policy limits. If set, and the state of a room contains a
          # 'm.room.retention' event in its state which contains a 'min_lifetime' or a
          # 'max_lifetime' that's out of these bounds, Synapse will cap the room's policy
          # to these limits when running purge jobs.
          #
          #allowed_lifetime_min: 1d
          #allowed_lifetime_max: 1y

          # Server admins can define the settings of the background jobs purging the
          # events which lifetime has expired under the 'purge_jobs' section.
          #
          # If no configuration is provided, a single job will be set up to delete expired
          # events in every room daily.
          #
          # Each job's configuration defines which range of message lifetimes the job
          # takes care of. For example, if 'shortest_max_lifetime' is '2d' and
          # 'longest_max_lifetime' is '3d', the job will handle purging expired events in
          # rooms whose state defines a 'max_lifetime' that's both higher than 2 days, and
          # lower than or equal to 3 days. Both the minimum and the maximum value of a
          # range are optional, e.g. a job with no 'shortest_max_lifetime' and a
          # 'longest_max_lifetime' of '3d' will handle every room with a retention policy
          # which 'max_lifetime' is lower than or equal to three days.
          #
          # The rationale for this per-job configuration is that some rooms might have a
          # retention policy with a low 'max_lifetime', where history needs to be purged
          # of outdated messages on a more frequent basis than for the rest of the rooms
          # (e.g. every 12h), but not want that purge to be performed by a job that's
          # iterating over every room it knows, which could be heavy on the server.
          #
          # If any purge job is configured, it is strongly recommended to have at least
          # a single job with neither 'shortest_max_lifetime' nor 'longest_max_lifetime'
          # set, or one job without 'shortest_max_lifetime' and one job without
          # 'longest_max_lifetime' set. Otherwise some rooms might be ignored, even if
          # 'allowed_lifetime_min' and 'allowed_lifetime_max' are set, because capping a
          # room's policy to these values is done after the policies are retrieved from
          # Synapse's database (which is done using the range specified in a purge job's
          # configuration).
          #
          #purge_jobs:
          #  - longest_max_lifetime: 3d
          #    interval: 12h
          #  - shortest_max_lifetime: 3d
          #    interval: 1d

        # Inhibits the /requestToken endpoints from returning an error that might leak
        # information about whether an e-mail address is in use or not on this
        # homeserver.
        # Note that for some endpoints the error situation is the e-mail already being
        # used, and for others the error is entering the e-mail being unused.
        # If this option is enabled, instead of returning an error, these endpoints will
        # act as if no error happened and return a fake session ID ('sid') to clients.
        #
        #request_token_inhibit_3pid_errors: true

        # A list of domains that the domain portion of 'next_link' parameters
        # must match.
        #
        # This parameter is optionally provided by clients while requesting
        # validation of an email or phone number, and maps to a link that
        # users will be automatically redirected to after validation
        # succeeds. Clients can make use this parameter to aid the validation
        # process.
        #
        # The whitelist is applied whether the homeserver or an
        # identity server is handling validation.
        #
        # The default value is no whitelist functionality; all domains are
        # allowed. Setting this value to an empty list will instead disallow
        # all domains.
        #
        #next_link_domain_whitelist: ["matrix.org"]
        """
            % locals()
        )

    def read_arguments(self, args):
        if args.manhole is not None:
            self.manhole = args.manhole
        if args.daemonize is not None:
            self.daemonize = args.daemonize
        if args.print_pidfile is not None:
            self.print_pidfile = args.print_pidfile

    @staticmethod
    def add_arguments(parser):
        server_group = parser.add_argument_group("server")
        server_group.add_argument(
            "-D",
            "--daemonize",
            action="store_true",
            default=None,
            help="Daemonize the homeserver",
        )
        server_group.add_argument(
            "--print-pidfile",
            action="store_true",
            default=None,
            help="Print the path to the pidfile just before daemonizing",
        )
        server_group.add_argument(
            "--manhole",
            metavar="PORT",
            dest="manhole",
            type=int,
            help="Turn on the twisted telnet manhole service on the given port.",
        )


def is_threepid_reserved(reserved_threepids, threepid):
    """Check the threepid against the reserved threepid config
    Args:
        reserved_threepids([dict]) - list of reserved threepids
        threepid(dict) - The threepid to test for

    Returns:
        boolean Is the threepid undertest reserved_user
    """

    for tp in reserved_threepids:
        if threepid["medium"] == tp["medium"] and threepid["address"] == tp["address"]:
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
        return (int(thresholds[0]), int(thresholds[1]), int(thresholds[2]))
    except Exception:
        raise ConfigError(
            "Value of `gc_threshold` must be a list of three integers if set"
        )


def parse_listener_def(listener: Any) -> ListenerConfig:
    """parse a listener config from the config file"""
    listener_type = listener["type"]

    port = listener.get("port")
    if not isinstance(port, int):
        raise ConfigError("Listener configuration is lacking a valid 'port' option")

    tls = listener.get("tls", False)

    bind_addresses = listener.get("bind_addresses", [])
    bind_address = listener.get("bind_address")
    # if bind_address was specified, add it to the list of addresses
    if bind_address:
        bind_addresses.append(bind_address)

    # if we still have an empty list of addresses, use the default list
    if not bind_addresses:
        if listener_type == "metrics":
            # the metrics listener doesn't support IPv6
            bind_addresses.append("0.0.0.0")
        else:
            bind_addresses.extend(DEFAULT_BIND_ADDRESSES)

    http_config = None
    if listener_type == "http":
        http_config = HttpListenerConfig(
            x_forwarded=listener.get("x_forwarded", False),
            resources=[
                HttpResourceConfig(**res) for res in listener.get("resources", [])
            ],
            additional_resources=listener.get("additional_resources", {}),
            tag=listener.get("tag"),
        )

    return ListenerConfig(port, bind_addresses, listener_type, tls, http_config)


NO_MORE_WEB_CLIENT_WARNING = """
Synapse no longer includes a web client. To enable a web client, configure
web_client_location. To remove this warning, remove 'webclient' from the 'listeners'
configuration.
"""


def _warn_if_webclient_configured(listeners: Iterable[ListenerConfig]) -> None:
    for listener in listeners:
        if not listener.http_options:
            continue
        for res in listener.http_options.resources:
            for name in res.names:
                if name == "webclient":
                    logger.warning(NO_MORE_WEB_CLIENT_WARNING)
                    return
