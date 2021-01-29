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

from typing import Dict

from ._base import Config


class RateLimitConfig:
    def __init__(
        self,
        config: Dict[str, float],
        defaults={"per_second": 0.17, "burst_count": 3.0},
    ):
        self.per_second = config.get("per_second", defaults["per_second"])
        self.burst_count = int(config.get("burst_count", defaults["burst_count"]))


class FederationRateLimitConfig:
    _items_and_default = {
        "window_size": 1000,
        "sleep_limit": 10,
        "sleep_delay": 500,
        "reject_limit": 50,
        "concurrent": 3,
    }

    def __init__(self, **kwargs):
        for i in self._items_and_default.keys():
            setattr(self, i, kwargs.get(i) or self._items_and_default[i])


class RatelimitConfig(Config):
    section = "ratelimiting"

    def read_config(self, config, **kwargs):

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
                    "window_size": config.get("federation_rc_window_size"),
                    "sleep_limit": config.get("federation_rc_sleep_limit"),
                    "sleep_delay": config.get("federation_rc_sleep_delay"),
                    "reject_limit": config.get("federation_rc_reject_limit"),
                    "concurrent": config.get("federation_rc_concurrent"),
                }
            )

        self.rc_registration = RateLimitConfig(config.get("rc_registration", {}))

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
            defaults={"per_second": 0.1, "burst_count": 3},
        )
        self.rc_joins_remote = RateLimitConfig(
            config.get("rc_joins", {}).get("remote", {}),
            defaults={"per_second": 0.01, "burst_count": 3},
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

    def generate_config_section(self, **kwargs):
        return """\
        ## Ratelimiting ##

        # Ratelimiting settings for client actions (registration, login, messaging).
        #
        # Each ratelimiting configuration is made of two parameters:
        #   - per_second: number of requests a client can send per second.
        #   - burst_count: number of requests a client can send before being throttled.
        #
        # Synapse currently uses the following configurations:
        #   - one for messages that ratelimits sending based on the account the client
        #     is using
        #   - one for registration that ratelimits registration requests based on the
        #     client's IP address.
        #   - one for login that ratelimits login requests based on the client's IP
        #     address.
        #   - one for login that ratelimits login requests based on the account the
        #     client is attempting to log into.
        #   - one for login that ratelimits login requests based on the account the
        #     client is attempting to log into, based on the amount of failed login
        #     attempts for this account.
        #   - one for ratelimiting redactions by room admins. If this is not explicitly
        #     set then it uses the same ratelimiting as per rc_message. This is useful
        #     to allow room admins to deal with abuse quickly.
        #   - two for ratelimiting number of rooms a user can join, "local" for when
        #     users are joining rooms the server is already in (this is cheap) vs
        #     "remote" for when users are trying to join rooms not on the server (which
        #     can be more expensive)
        #   - one for ratelimiting how often a user or IP can attempt to validate a 3PID.
        #   - two for ratelimiting how often invites can be sent in a room or to a
        #     specific user.
        #
        # The defaults are as shown below.
        #
        #rc_message:
        #  per_second: 0.2
        #  burst_count: 10
        #
        #rc_registration:
        #  per_second: 0.17
        #  burst_count: 3
        #
        #rc_login:
        #  address:
        #    per_second: 0.17
        #    burst_count: 3
        #  account:
        #    per_second: 0.17
        #    burst_count: 3
        #  failed_attempts:
        #    per_second: 0.17
        #    burst_count: 3
        #
        #rc_admin_redaction:
        #  per_second: 1
        #  burst_count: 50
        #
        #rc_joins:
        #  local:
        #    per_second: 0.1
        #    burst_count: 3
        #  remote:
        #    per_second: 0.01
        #    burst_count: 3
        #
        #rc_3pid_validation:
        #  per_second: 0.003
        #  burst_count: 5
        #
        #rc_invites:
        #  per_room:
        #    per_second: 0.3
        #    burst_count: 10
        #  per_user:
        #    per_second: 0.003
        #    burst_count: 5

        # Ratelimiting settings for incoming federation
        #
        # The rc_federation configuration is made up of the following settings:
        #   - window_size: window size in milliseconds
        #   - sleep_limit: number of federation requests from a single server in
        #     a window before the server will delay processing the request.
        #   - sleep_delay: duration in milliseconds to delay processing events
        #     from remote servers by if they go over the sleep limit.
        #   - reject_limit: maximum number of concurrent federation requests
        #     allowed from a single server
        #   - concurrent: number of federation requests to concurrently process
        #     from a single server
        #
        # The defaults are as shown below.
        #
        #rc_federation:
        #  window_size: 1000
        #  sleep_limit: 10
        #  sleep_delay: 500
        #  reject_limit: 50
        #  concurrent: 3

        # Target outgoing federation transaction frequency for sending read-receipts,
        # per-room.
        #
        # If we end up trying to send out more read-receipts, they will get buffered up
        # into fewer transactions.
        #
        #federation_rr_transactions_per_room_per_second: 50
        """
