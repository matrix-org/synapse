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

        self.federation_ip_range_blacklist = config.get(
            "federation_ip_range_blacklist", []
        )

        # Attempt to create an IPSet from the given ranges
        try:
            self.federation_ip_range_blacklist = IPSet(
                self.federation_ip_range_blacklist
            )

            # Always blacklist 0.0.0.0, ::
            self.federation_ip_range_blacklist.update(["0.0.0.0", "::"])
        except Exception as e:
            raise ConfigError(
                "Invalid range(s) provided in federation_ip_range_blacklist: %s" % e
            )

        federation_metrics_domains = config.get("federation_metrics_domains") or []
        validate_config(
            _METRICS_FOR_DOMAINS_SCHEMA,
            federation_metrics_domains,
            ("federation_metrics_domains",),
        )
        self.federation_metrics_domains = set(federation_metrics_domains)

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
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

        # Prevent federation requests from being sent to the following
        # blacklist IP address CIDR ranges. If this option is not specified, or
        # specified with an empty list, no ip range blacklist will be enforced.
        #
        # As of Synapse v1.4.0 this option also affects any outbound requests to identity
        # servers provided by user input.
        #
        # (0.0.0.0 and :: are always blacklisted, whether or not they are explicitly
        # listed here, since they correspond to unroutable addresses.)
        #
        federation_ip_range_blacklist:
          - '127.0.0.0/8'
          - '10.0.0.0/8'
          - '172.16.0.0/12'
          - '192.168.0.0/16'
          - '100.64.0.0/10'
          - '169.254.0.0/16'
          - '::1/128'
          - 'fe80::/64'
          - 'fc00::/7'

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
        """


_METRICS_FOR_DOMAINS_SCHEMA = {"type": "array", "items": {"type": "string"}}
