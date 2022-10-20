# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
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
import itertools
import logging
import os.path
import urllib.parse
from textwrap import indent
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import attr
import yaml
from netaddr import AddrFormatError, IPNetwork, IPSet

from twisted.conch.ssh.keys import Key

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.types import JsonDict
from synapse.util.module_loader import load_module
from synapse.util.stringutils import parse_and_validate_server_name

from ._base import Config, ConfigError
from ._util import validate_config

logger = logging.Logger(__name__)

DIRECT_TCP_ERROR = """
Using direct TCP replication for workers is no longer supported.

Please see https://matrix-org.github.io/synapse/latest/upgrade.html#direct-tcp-replication-is-no-longer-supported-migrate-to-redis
"""

# by default, we attempt to listen on both '::' *and* '0.0.0.0' because some OSes
# (Windows, macOS, other BSD/Linux where net.ipv6.bindv6only is set) will only listen
# on IPv6 when '::' is set.
#
# We later check for errors when binding to 0.0.0.0 and ignore them if :: is also in
# in the list.
DEFAULT_BIND_ADDRESSES = ["::", "0.0.0.0"]


def _6to4(network: IPNetwork) -> IPNetwork:
    """Convert an IPv4 network into a 6to4 IPv6 network per RFC 3056."""

    # 6to4 networks consist of:
    # * 2002 as the first 16 bits
    # * The first IPv4 address in the network hex-encoded as the next 32 bits
    # * The new prefix length needs to include the bits from the 2002 prefix.
    hex_network = hex(network.first)[2:]
    hex_network = ("0" * (8 - len(hex_network))) + hex_network
    return IPNetwork(
        "2002:%s:%s::/%d"
        % (
            hex_network[:4],
            hex_network[4:],
            16 + network.prefixlen,
        )
    )


def generate_ip_set(
    ip_addresses: Optional[Iterable[str]],
    extra_addresses: Optional[Iterable[str]] = None,
    config_path: Optional[Iterable[str]] = None,
) -> IPSet:
    """
    Generate an IPSet from a list of IP addresses or CIDRs.

    Additionally, for each IPv4 network in the list of IP addresses, also
    includes the corresponding IPv6 networks.

    This includes:

    * IPv4-Compatible IPv6 Address (see RFC 4291, section 2.5.5.1)
    * IPv4-Mapped IPv6 Address (see RFC 4291, section 2.5.5.2)
    * 6to4 Address (see RFC 3056, section 2)

    Args:
        ip_addresses: An iterable of IP addresses or CIDRs.
        extra_addresses: An iterable of IP addresses or CIDRs.
        config_path: The path in the configuration for error messages.

    Returns:
        A new IP set.
    """
    result = IPSet()
    for ip in itertools.chain(ip_addresses or (), extra_addresses or ()):
        try:
            network = IPNetwork(ip)
        except AddrFormatError as e:
            raise ConfigError(
                "Invalid IP range provided: %s." % (ip,), config_path
            ) from e
        result.add(network)

        # It is possible that these already exist in the set, but that's OK.
        if ":" not in str(network):
            result.add(IPNetwork(network).ipv6(ipv4_compatible=True))
            result.add(IPNetwork(network).ipv6(ipv4_compatible=False))
            result.add(_6to4(network))

    return result


# IP ranges that are considered private / unroutable / don't make sense.
DEFAULT_IP_RANGE_BLACKLIST = [
    # Localhost
    "127.0.0.0/8",
    # Private networks.
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # Carrier grade NAT.
    "100.64.0.0/10",
    # Address registry.
    "192.0.0.0/24",
    # Link-local networks.
    "169.254.0.0/16",
    # Formerly used for 6to4 relay.
    "192.88.99.0/24",
    # Testing networks.
    "198.18.0.0/15",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    # Multicast.
    "224.0.0.0/4",
    # Localhost
    "::1/128",
    # Link-local addresses.
    "fe80::/10",
    # Unique local addresses.
    "fc00::/7",
    # Testing networks.
    "2001:db8::/32",
    # Multicast.
    "ff00::/8",
    # Site-local addresses
    "fec0::/10",
]

DEFAULT_ROOM_VERSION = "9"

ROOM_COMPLEXITY_TOO_GREAT = (
    "Your homeserver is unable to join rooms this large or complex. "
    "Please speak to your server administrator, or upgrade your instance "
    "to join this room."
)

METRICS_PORT_WARNING = """\
The metrics_port configuration option is deprecated in Synapse 0.31 in favour of
a listener. Please see
https://matrix-org.github.io/synapse/latest/metrics-howto.html
on how to configure the new listener.
--------------------------------------------------------------------------------"""


KNOWN_LISTENER_TYPES = {
    "http",
    "metrics",
    "manhole",
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
}


@attr.s(frozen=True)
class HttpResourceConfig:
    names: List[str] = attr.ib(
        factory=list,
        validator=attr.validators.deep_iterable(attr.validators.in_(KNOWN_RESOURCES)),
    )
    compress: bool = attr.ib(
        default=False,
        validator=attr.validators.optional(attr.validators.instance_of(bool)),  # type: ignore[arg-type]
    )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class HttpListenerConfig:
    """Object describing the http-specific parts of the config of a listener"""

    x_forwarded: bool = False
    resources: List[HttpResourceConfig] = attr.Factory(list)
    additional_resources: Dict[str, dict] = attr.Factory(dict)
    tag: Optional[str] = None
    request_id_header: Optional[str] = None
    # If true, the listener will return CORS response headers compatible with MSC3886:
    # https://github.com/matrix-org/matrix-spec-proposals/pull/3886
    experimental_cors_msc3886: bool = False


@attr.s(slots=True, frozen=True, auto_attribs=True)
class ListenerConfig:
    """Object describing the configuration of a single listener."""

    port: int = attr.ib(validator=attr.validators.instance_of(int))
    bind_addresses: List[str]
    type: str = attr.ib(validator=attr.validators.in_(KNOWN_LISTENER_TYPES))
    tls: bool = False

    # http_options is only populated if type=http
    http_options: Optional[HttpListenerConfig] = None


@attr.s(slots=True, frozen=True, auto_attribs=True)
class ManholeConfig:
    """Object describing the configuration of the manhole"""

    username: str = attr.ib(validator=attr.validators.instance_of(str))
    password: str = attr.ib(validator=attr.validators.instance_of(str))
    priv_key: Optional[Key]
    pub_key: Optional[Key]


@attr.s(frozen=True)
class LimitRemoteRoomsConfig:
    enabled: bool = attr.ib(validator=attr.validators.instance_of(bool), default=False)
    complexity: Union[float, int] = attr.ib(
        validator=attr.validators.instance_of((float, int)),  # noqa
        default=1.0,
    )
    complexity_error: str = attr.ib(
        validator=attr.validators.instance_of(str),
        default=ROOM_COMPLEXITY_TOO_GREAT,
    )
    admins_can_join: bool = attr.ib(
        validator=attr.validators.instance_of(bool), default=False
    )


class ServerConfig(Config):
    section = "server"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.server_name = config["server_name"]
        self.server_context = config.get("server_context", None)

        try:
            parse_and_validate_server_name(self.server_name)
        except ValueError as e:
            raise ConfigError(str(e))

        self.pid_file = self.abspath(config.get("pid_file"))
        self.soft_file_limit = config.get("soft_file_limit", 0)
        self.daemonize = bool(config.get("daemonize"))
        self.print_pidfile = bool(config.get("print_pidfile"))
        self.user_agent_suffix = config.get("user_agent_suffix")
        self.use_frozen_dicts = config.get("use_frozen_dicts", False)
        self.serve_server_wellknown = config.get("serve_server_wellknown", False)

        # Whether we should serve a "client well-known":
        #  (a) at .well-known/matrix/client on our client HTTP listener
        #  (b) in the response to /login
        #
        # ... which together help ensure that clients use our public_baseurl instead of
        # whatever they were told by the user.
        #
        # For the sake of backwards compatibility with existing installations, this is
        # True if public_baseurl is specified explicitly, and otherwise False. (The
        # reasoning here is that we have no way of knowing that the default
        # public_baseurl is actually correct for existing installations - many things
        # will not work correctly, but that's (probably?) better than sending clients
        # to a completely broken URL.
        self.serve_client_wellknown = False

        public_baseurl = config.get("public_baseurl")
        if public_baseurl is None:
            public_baseurl = f"https://{self.server_name}/"
            logger.info("Using default public_baseurl %s", public_baseurl)
        else:
            self.serve_client_wellknown = True
            if public_baseurl[-1] != "/":
                public_baseurl += "/"
        self.public_baseurl = public_baseurl

        # check that public_baseurl is valid
        try:
            splits = urllib.parse.urlsplit(self.public_baseurl)
        except Exception as e:
            raise ConfigError(f"Unable to parse URL: {e}", ("public_baseurl",))
        if splits.scheme not in ("https", "http"):
            raise ConfigError(
                f"Invalid scheme '{splits.scheme}': only https and http are supported"
            )
        if splits.query or splits.fragment:
            raise ConfigError(
                "public_baseurl cannot contain query parameters or a #-fragment"
            )

        self.extra_well_known_client_content = config.get(
            "extra_well_known_client_content", {}
        )

        if not isinstance(self.extra_well_known_client_content, dict):
            raise ConfigError(
                "extra_well_known_content must be a dictionary of key-value pairs"
            )

        if "m.homeserver" in self.extra_well_known_client_content:
            raise ConfigError(
                "m.homeserver is not supported in extra_well_known_content, "
                "use public_baseurl in base config instead."
            )
        if "m.identity_server" in self.extra_well_known_client_content:
            raise ConfigError(
                "m.identity_server is not supported in extra_well_known_content, "
                "use default_identity_server in base config instead."
            )

        # Whether to enable user presence.
        presence_config = config.get("presence") or {}
        self.use_presence = presence_config.get("enabled")
        if self.use_presence is None:
            self.use_presence = config.get("use_presence", True)

        # Custom presence router module
        # This is the legacy way of configuring it (the config should now be put in the modules section)
        self.presence_router_module_class = None
        self.presence_router_config = None
        presence_router_config = presence_config.get("presence_router")
        if presence_router_config:
            (
                self.presence_router_module_class,
                self.presence_router_config,
            ) = load_module(presence_router_config, ("presence", "presence_router"))

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
            "limit_profile_requests_to_users_who_share_rooms",
            False,
        )

        # Whether to retrieve and display profile data for a user when they
        # are invited to a room
        self.include_profile_data_on_invite = config.get(
            "include_profile_data_on_invite", True
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
        self.mau_appservice_trial_days = config.get("mau_appservice_trial_days", {})
        self.mau_limit_alerting = config.get("mau_limit_alerting", True)

        # How long to keep redacted events in the database in unredacted form
        # before redacting them.
        redaction_retention_period = config.get("redaction_retention_period", "7d")
        if redaction_retention_period is not None:
            self.redaction_retention_period: Optional[int] = self.parse_duration(
                redaction_retention_period
            )
        else:
            self.redaction_retention_period = None

        # How long to keep entries in the `users_ips` table.
        user_ips_max_age = config.get("user_ips_max_age", "28d")
        if user_ips_max_age is not None:
            self.user_ips_max_age: Optional[int] = self.parse_duration(user_ips_max_age)
        else:
            self.user_ips_max_age = None

        # Options to disable HS
        self.hs_disabled = config.get("hs_disabled", False)
        self.hs_disabled_message = config.get("hs_disabled_message", "")

        # Admin uri to direct users at should their instance become blocked
        # due to resource constraints
        self.admin_contact = config.get("admin_contact", None)

        ip_range_blacklist = config.get(
            "ip_range_blacklist", DEFAULT_IP_RANGE_BLACKLIST
        )

        # Attempt to create an IPSet from the given ranges

        # Always blacklist 0.0.0.0, ::
        self.ip_range_blacklist = generate_ip_set(
            ip_range_blacklist, ["0.0.0.0", "::"], config_path=("ip_range_blacklist",)
        )

        self.ip_range_whitelist = generate_ip_set(
            config.get("ip_range_whitelist", ()), config_path=("ip_range_whitelist",)
        )
        # The federation_ip_range_blacklist is used for backwards-compatibility
        # and only applies to federation and identity servers.
        if "federation_ip_range_blacklist" in config:
            # Always blacklist 0.0.0.0, ::
            self.federation_ip_range_blacklist = generate_ip_set(
                config["federation_ip_range_blacklist"],
                ["0.0.0.0", "::"],
                config_path=("federation_ip_range_blacklist",),
            )
            # 'federation_ip_range_whitelist' was never a supported configuration option.
            self.federation_ip_range_whitelist = None
        else:
            # No backwards-compatiblity requrired, as federation_ip_range_blacklist
            # is not given. Default to ip_range_blacklist and ip_range_whitelist.
            self.federation_ip_range_blacklist = self.ip_range_blacklist
            self.federation_ip_range_whitelist = self.ip_range_whitelist

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

        # The maximum size an avatar can have, in bytes.
        self.max_avatar_size = config.get("max_avatar_size")
        if self.max_avatar_size is not None:
            self.max_avatar_size = self.parse_size(self.max_avatar_size)

        # The MIME types allowed for an avatar.
        self.allowed_avatar_mimetypes = config.get("allowed_avatar_mimetypes")
        if self.allowed_avatar_mimetypes and not isinstance(
            self.allowed_avatar_mimetypes,
            list,
        ):
            raise ConfigError("allowed_avatar_mimetypes must be a list")

        listeners = config.get("listeners", [])
        if not isinstance(listeners, list):
            raise ConfigError("Expected a list", ("listeners",))

        self.listeners = [parse_listener_def(i, x) for i, x in enumerate(listeners)]

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

        self.web_client_location = config.get("web_client_location", None)
        # Non-HTTP(S) web client location is not supported.
        if self.web_client_location and not (
            self.web_client_location.startswith("http://")
            or self.web_client_location.startswith("https://")
        ):
            raise ConfigError("web_client_location must point to a HTTP(S) URL.")

        self.gc_thresholds = read_gc_thresholds(config.get("gc_thresholds", None))
        self.gc_seconds = self.read_gc_intervals(config.get("gc_min_interval", None))

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
                    port=manhole,
                    bind_addresses=["127.0.0.1"],
                    type="manhole",
                )
            )

        manhole_settings = config.get("manhole_settings") or {}
        validate_config(
            _MANHOLE_SETTINGS_SCHEMA, manhole_settings, ("manhole_settings",)
        )

        manhole_username = manhole_settings.get("username", "matrix")
        manhole_password = manhole_settings.get("password", "rabbithole")
        manhole_priv_key_path = manhole_settings.get("ssh_priv_key_path")
        manhole_pub_key_path = manhole_settings.get("ssh_pub_key_path")

        manhole_priv_key = None
        if manhole_priv_key_path is not None:
            try:
                manhole_priv_key = Key.fromFile(manhole_priv_key_path)
            except Exception as e:
                raise ConfigError(
                    f"Failed to read manhole private key file {manhole_priv_key_path}"
                ) from e

        manhole_pub_key = None
        if manhole_pub_key_path is not None:
            try:
                manhole_pub_key = Key.fromFile(manhole_pub_key_path)
            except Exception as e:
                raise ConfigError(
                    f"Failed to read manhole public key file {manhole_pub_key_path}"
                ) from e

        self.manhole_settings = ManholeConfig(
            username=manhole_username,
            password=manhole_password,
            priv_key=manhole_priv_key,
            pub_key=manhole_pub_key,
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
            "request_token_inhibit_3pid_errors",
            False,
        )

        # Whitelist of domain names that given next_link parameters must have
        next_link_domain_whitelist: Optional[List[str]] = config.get(
            "next_link_domain_whitelist"
        )

        self.next_link_domain_whitelist: Optional[Set[str]] = None
        if next_link_domain_whitelist is not None:
            if not isinstance(next_link_domain_whitelist, list):
                raise ConfigError("'next_link_domain_whitelist' must be a list")

            # Turn the list into a set to improve lookup speed.
            self.next_link_domain_whitelist = set(next_link_domain_whitelist)

        templates_config = config.get("templates") or {}
        if not isinstance(templates_config, dict):
            raise ConfigError("The 'templates' section must be a dictionary")

        self.custom_template_directory: Optional[str] = templates_config.get(
            "custom_template_directory"
        )
        if self.custom_template_directory is not None and not isinstance(
            self.custom_template_directory, str
        ):
            raise ConfigError("'custom_template_directory' must be a string")

        self.use_account_validity_in_account_status: bool = (
            config.get("use_account_validity_in_account_status") or False
        )

        self.rooms_to_exclude_from_sync: List[str] = (
            config.get("exclude_rooms_from_sync") or []
        )

        delete_stale_devices_after: Optional[str] = (
            config.get("delete_stale_devices_after") or None
        )

        if delete_stale_devices_after is not None:
            self.delete_stale_devices_after: Optional[int] = self.parse_duration(
                delete_stale_devices_after
            )
        else:
            self.delete_stale_devices_after = None

    def has_tls_listener(self) -> bool:
        return any(listener.tls for listener in self.listeners)

    def generate_config_section(
        self,
        config_dir_path: str,
        data_dir_path: str,
        server_name: str,
        open_private_ports: bool,
        listeners: Optional[List[dict]],
        **kwargs: Any,
    ) -> str:

        _, bind_port = parse_and_validate_server_name(server_name)
        if bind_port is not None:
            unsecure_port = bind_port - 400
        else:
            bind_port = 8448
            unsecure_port = 8008

        pid_file = os.path.join(data_dir_path, "homeserver.pid")

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
                unsecure_http_bindings = ""

        if not secure_listeners:
            secure_http_bindings = ""

        return (
            """\
        server_name: "%(server_name)s"
        pid_file: %(pid_file)s
        listeners:
          %(secure_http_bindings)s
          %(unsecure_http_bindings)s
        """
            % locals()
        )

    def read_arguments(self, args: argparse.Namespace) -> None:
        if args.manhole is not None:
            self.manhole = args.manhole
        if args.daemonize is not None:
            self.daemonize = args.daemonize
        if args.print_pidfile is not None:
            self.print_pidfile = args.print_pidfile

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
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

    def read_gc_intervals(self, durations: Any) -> Optional[Tuple[float, float, float]]:
        """Reads the three durations for the GC min interval option, returning seconds."""
        if durations is None:
            return None

        try:
            if len(durations) != 3:
                raise ValueError()
            return (
                self.parse_duration(durations[0]) / 1000,
                self.parse_duration(durations[1]) / 1000,
                self.parse_duration(durations[2]) / 1000,
            )
        except Exception:
            raise ConfigError(
                "Value of `gc_min_interval` must be a list of three durations if set"
            )


def is_threepid_reserved(
    reserved_threepids: List[JsonDict], threepid: JsonDict
) -> bool:
    """Check the threepid against the reserved threepid config
    Args:
        reserved_threepids: List of reserved threepids
        threepid: The threepid to test for

    Returns:
        Is the threepid undertest reserved_user
    """

    for tp in reserved_threepids:
        if threepid["medium"] == tp["medium"] and threepid["address"] == tp["address"]:
            return True
    return False


def read_gc_thresholds(
    thresholds: Optional[List[Any]],
) -> Optional[Tuple[int, int, int]]:
    """Reads the three integer thresholds for garbage collection. Ensures that
    the thresholds are integers if thresholds are supplied.
    """
    if thresholds is None:
        return None
    try:
        assert len(thresholds) == 3
        return int(thresholds[0]), int(thresholds[1]), int(thresholds[2])
    except Exception:
        raise ConfigError(
            "Value of `gc_threshold` must be a list of three integers if set"
        )


def parse_listener_def(num: int, listener: Any) -> ListenerConfig:
    """parse a listener config from the config file"""
    if not isinstance(listener, dict):
        raise ConfigError("Expected a dictionary", ("listeners", str(num)))

    listener_type = listener["type"]
    # Raise a helpful error if direct TCP replication is still configured.
    if listener_type == "replication":
        raise ConfigError(DIRECT_TCP_ERROR, ("listeners", str(num), "type"))

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
        try:
            resources = [
                HttpResourceConfig(**res) for res in listener.get("resources", [])
            ]
        except ValueError as e:
            raise ConfigError("Unknown listener resource") from e

        http_config = HttpListenerConfig(
            x_forwarded=listener.get("x_forwarded", False),
            resources=resources,
            additional_resources=listener.get("additional_resources", {}),
            tag=listener.get("tag"),
            request_id_header=listener.get("request_id_header"),
            experimental_cors_msc3886=listener.get("experimental_cors_msc3886", False),
        )

    return ListenerConfig(port, bind_addresses, listener_type, tls, http_config)


_MANHOLE_SETTINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"},
        "ssh_priv_key_path": {"type": "string"},
        "ssh_pub_key_path": {"type": "string"},
    },
}
