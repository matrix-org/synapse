# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import Optional

from netaddr import IPSet

from synapse.config._base import Config, ConfigError
from synapse.config._util import validate_config

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
]


class FederationConfig(Config):
    section = "federation"

    def read_config(self, config, **kwargs):
        # FIXME: federation_domain_whitelist needs sytests
        self.federation_domain_whitelist = None  # type: Optional[dict]
        federation_domain_whitelist = config.get("federation_domain_whitelist", None)

        if federation_domain_whitelist is not None:
            # turn the whitelist into a hash for speed of lookup
            self.federation_domain_whitelist = {}

            for domain in federation_domain_whitelist:
                self.federation_domain_whitelist[domain] = True

        ip_range_blacklist = config.get(
            "ip_range_blacklist", DEFAULT_IP_RANGE_BLACKLIST
        )

        # Attempt to create an IPSet from the given ranges
        try:
            self.ip_range_blacklist = IPSet(ip_range_blacklist)
        except Exception as e:
            raise ConfigError("Invalid range(s) provided in ip_range_blacklist: %s" % e)
        # Always blacklist 0.0.0.0, ::
        self.ip_range_blacklist.update(["0.0.0.0", "::"])

        try:
            self.ip_range_whitelist = IPSet(config.get("ip_range_whitelist", ()))
        except Exception as e:
            raise ConfigError("Invalid range(s) provided in ip_range_whitelist: %s" % e)

        # The federation_ip_range_blacklist is used for backwards-compatibility
        # and only applies to federation and identity servers. If it is not given,
        # default to ip_range_blacklist.
        federation_ip_range_blacklist = config.get(
            "federation_ip_range_blacklist", ip_range_blacklist
        )
        try:
            self.federation_ip_range_blacklist = IPSet(federation_ip_range_blacklist)
        except Exception as e:
            raise ConfigError(
                "Invalid range(s) provided in federation_ip_range_blacklist: %s" % e
            )
        # Always blacklist 0.0.0.0, ::
        self.federation_ip_range_blacklist.update(["0.0.0.0", "::"])

        federation_metrics_domains = config.get("federation_metrics_domains") or []
        validate_config(
            _METRICS_FOR_DOMAINS_SCHEMA,
            federation_metrics_domains,
            ("federation_metrics_domains",),
        )
        self.federation_metrics_domains = set(federation_metrics_domains)

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        ip_range_blacklist = "\n".join(
            "        #  - '%s'" % ip for ip in DEFAULT_IP_RANGE_BLACKLIST
        )

        return """\
        ## Federation ##

        # Restrict federation to the following whitelist of domains.
        # N.B. we recommend also firewalling your federation listener to limit
        # inbound federation traffic as early as possible, rather than relying
        # purely on this application-layer restriction.  If not specified, the
        # default is to whitelist everything.
        #
        #federation_domain_whitelist:
        #  - lon.example.com
        #  - nyc.example.com
        #  - syd.example.com

        # Prevent outgoing requests from being sent to the following blacklisted IP address
        # CIDR ranges. If this option is not specified or is empty then it defaults to
        # private IP address ranges (see the example below).
        #
        # The blacklist applies to the outbound requests for federation, identity servers,
        # push servers, and for checking key validity for third-party invite events.
        #
        # (0.0.0.0 and :: are always blacklisted, whether or not they are explicitly
        # listed here, since they correspond to unroutable addresses.)
        #
        # This option replaces federation_ip_range_blacklist in Synapse v1.24.0.
        #
        #ip_range_blacklist:
%(ip_range_blacklist)s

        # List of IP address CIDR ranges that should be allowed for federation,
        # identity servers, push servers, and for checking key validity for
        # third-party invite events. This is useful for specifying exceptions to
        # wide-ranging blacklisted target IP ranges - e.g. for communication with
        # a push server only visible in your network.
        #
        # This whitelist overrides ip_range_blacklist and defaults to an empty
        # list.
        #
        #ip_range_whitelist:
        #   - '192.168.1.1'

        # Report prometheus metrics on the age of PDUs being sent to and received from
        # the following domains. This can be used to give an idea of "delay" on inbound
        # and outbound federation, though be aware that any delay can be due to problems
        # at either end or with the intermediate network.
        #
        # By default, no domains are monitored in this way.
        #
        #federation_metrics_domains:
        #  - matrix.org
        #  - example.com
        """ % {"ip_range_blacklist": ip_range_blacklist}


_METRICS_FOR_DOMAINS_SCHEMA = {"type": "array", "items": {"type": "string"}}
