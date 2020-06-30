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

from hashlib import sha256
from typing import List, Optional

import attr
from netaddr import IPSet

from ._base import Config, ConfigError


@attr.s
class ShardedFederationSendingConfig:
    """Algorithm for choosing which federation sender instance is responsible
    for which destionation host.
    """

    instances = attr.ib(type=List[str])

    def should_send_to(self, instance_name: str, destination: str) -> bool:
        """Whether this instance is responsible for sending transcations for
        the given host.
        """

        # If multiple federation senders are not defined we always return true.
        if not self.instances or len(self.instances) == 1:
            return True

        # We shard by taking the hash, modulo it by the number of federation
        # senders and then checking whether this instance matches the instance
        # at that index.
        #
        # (Technically this introduces some bias and is not entirely uniform, but
        # since the hash is so large the bias is ridiculously small).
        dest_hash = sha256(destination.encode("utf8")).digest()
        dest_int = int.from_bytes(dest_hash, byteorder="little")
        remainder = dest_int % (len(self.instances))
        return self.instances[remainder] == instance_name


class FederationConfig(Config):
    section = "federation"

    def read_config(self, config, **kwargs):
        # Whether to send federation traffic out in this process. This only
        # applies to some federation traffic, and so shouldn't be used to
        # "disable" federation
        self.send_federation = config.get("send_federation", True)

        federation_sender_instances = config.get("federation_sender_instances") or []
        self.federation_shard_config = ShardedFederationSendingConfig(
            federation_sender_instances
        )

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

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
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
        """
