# Copyright 2014-2016 OpenMarket Ltd
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

from typing import Any, Dict, Optional

import attr

from synapse.types import JsonDict

from ._base import Config


class RateLimitConfig:
    def __init__(
        self,
        config: Dict[str, float],
        defaults: Optional[Dict[str, float]] = None,
    ):
        defaults = defaults or {"per_second": 0.17, "burst_count": 3.0}

        self.per_second = config.get("per_second", defaults["per_second"])
        self.burst_count = int(config.get("burst_count", defaults["burst_count"]))


@attr.s(auto_attribs=True)
class FederationRateLimitConfig:
    window_size: int = 1000
    sleep_limit: int = 10
    sleep_delay: int = 500
    reject_limit: int = 50
    concurrent: int = 3


class RatelimitConfig(Config):
    section = "ratelimiting"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:

        # Load the new-style messages config if it exists. Otherwise fall back
        # to the old method.
        if "rc_message" in config:
            self.rc_message = RateLimitConfig(
                config["rc_message"], defaults={"per_second": 0.2, "burst_count": 10.0}
            )
        else:
            self.rc_message = RateLimitConfig(
                {
                    "per_second": config.get("rc_messages_per_second", 0.2),
                    "burst_count": config.get("rc_message_burst_count", 10.0),
                }
            )

        # Load the new-style federation config, if it exists. Otherwise, fall
        # back to the old method.
        if "rc_federation" in config:
            self.rc_federation = FederationRateLimitConfig(**config["rc_federation"])
        else:
            self.rc_federation = FederationRateLimitConfig(
                **{
                    k: v
                    for k, v in {
                        "window_size": config.get("federation_rc_window_size"),
                        "sleep_limit": config.get("federation_rc_sleep_limit"),
                        "sleep_delay": config.get("federation_rc_sleep_delay"),
                        "reject_limit": config.get("federation_rc_reject_limit"),
                        "concurrent": config.get("federation_rc_concurrent"),
                    }.items()
                    if v is not None
                }
            )

        self.rc_registration = RateLimitConfig(config.get("rc_registration", {}))

        self.rc_registration_token_validity = RateLimitConfig(
            config.get("rc_registration_token_validity", {}),
            defaults={"per_second": 0.1, "burst_count": 5},
        )

        rc_login_config = config.get("rc_login", {})
        self.rc_login_address = RateLimitConfig(rc_login_config.get("address", {}))
        self.rc_login_account = RateLimitConfig(rc_login_config.get("account", {}))
        self.rc_login_failed_attempts = RateLimitConfig(
            rc_login_config.get("failed_attempts", {})
        )

        self.federation_rr_transactions_per_room_per_second = config.get(
            "federation_rr_transactions_per_room_per_second", 50
        )

        rc_admin_redaction = config.get("rc_admin_redaction")
        self.rc_admin_redaction = None
        if rc_admin_redaction:
            self.rc_admin_redaction = RateLimitConfig(rc_admin_redaction)

        self.rc_joins_local = RateLimitConfig(
            config.get("rc_joins", {}).get("local", {}),
            defaults={"per_second": 0.1, "burst_count": 10},
        )
        self.rc_joins_remote = RateLimitConfig(
            config.get("rc_joins", {}).get("remote", {}),
            defaults={"per_second": 0.01, "burst_count": 10},
        )

        # Ratelimit cross-user key requests:
        # * For local requests this is keyed by the sending device.
        # * For requests received over federation this is keyed by the origin.
        #
        # Note that this isn't exposed in the configuration as it is obscure.
        self.rc_key_requests = RateLimitConfig(
            config.get("rc_key_requests", {}),
            defaults={"per_second": 20, "burst_count": 100},
        )

        self.rc_3pid_validation = RateLimitConfig(
            config.get("rc_3pid_validation") or {},
            defaults={"per_second": 0.003, "burst_count": 5},
        )

        self.rc_invites_per_room = RateLimitConfig(
            config.get("rc_invites", {}).get("per_room", {}),
            defaults={"per_second": 0.3, "burst_count": 10},
        )
        self.rc_invites_per_user = RateLimitConfig(
            config.get("rc_invites", {}).get("per_user", {}),
            defaults={"per_second": 0.003, "burst_count": 5},
        )

        self.rc_invites_per_issuer = RateLimitConfig(
            config.get("rc_invites", {}).get("per_issuer", {}),
            defaults={"per_second": 0.3, "burst_count": 10},
        )

        self.rc_third_party_invite = RateLimitConfig(
            config.get("rc_third_party_invite", {}),
            defaults={
                "per_second": self.rc_message.per_second,
                "burst_count": self.rc_message.burst_count,
            },
        )
