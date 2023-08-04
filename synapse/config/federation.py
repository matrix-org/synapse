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
from typing import Any, Optional

from synapse.config._base import Config
from synapse.config._util import validate_config
from synapse.types import JsonDict


class FederationConfig(Config):
    section = "federation"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        federation_config = config.setdefault("federation", {})

        # FIXME: federation_domain_whitelist needs sytests
        self.federation_domain_whitelist: Optional[dict] = None
        federation_domain_whitelist = config.get("federation_domain_whitelist", None)

        if federation_domain_whitelist is not None:
            # turn the whitelist into a hash for speed of lookup
            self.federation_domain_whitelist = {}

            for domain in federation_domain_whitelist:
                self.federation_domain_whitelist[domain] = True

        federation_metrics_domains = config.get("federation_metrics_domains") or []
        validate_config(
            _METRICS_FOR_DOMAINS_SCHEMA,
            federation_metrics_domains,
            ("federation_metrics_domains",),
        )
        self.federation_metrics_domains = set(federation_metrics_domains)

        self.allow_profile_lookup_over_federation = config.get(
            "allow_profile_lookup_over_federation", True
        )

        self.allow_device_name_lookup_over_federation = config.get(
            "allow_device_name_lookup_over_federation", False
        )

        # Allow for the configuration of timeout, max request retries
        # and min/max retry delays in the matrix federation client.
        self.client_timeout_ms = Config.parse_duration(
            federation_config.get("client_timeout", "60s")
        )
        self.max_long_retry_delay_ms = Config.parse_duration(
            federation_config.get("max_long_retry_delay", "60s")
        )
        self.max_short_retry_delay_ms = Config.parse_duration(
            federation_config.get("max_short_retry_delay", "2s")
        )
        self.max_long_retries = federation_config.get("max_long_retries", 10)
        self.max_short_retries = federation_config.get("max_short_retries", 3)

        # Allow for the configuration of the backoff algorithm used
        # when trying to reach an unavailable destination.
        # Unlike previous configuration those values applies across
        # multiple requests and the state of the backoff is stored on DB.
        self.destination_min_retry_interval_ms = Config.parse_duration(
            federation_config.get("destination_min_retry_interval", "10m")
        )
        self.destination_retry_multiplier = federation_config.get(
            "destination_retry_multiplier", 2
        )
        self.destination_max_retry_interval_ms = min(
            Config.parse_duration(
                federation_config.get("destination_max_retry_interval", "7d")
            ),
            # Set a hard-limit to not overflow the database column.
            2**62,
        )


_METRICS_FOR_DOMAINS_SCHEMA = {"type": "array", "items": {"type": "string"}}
