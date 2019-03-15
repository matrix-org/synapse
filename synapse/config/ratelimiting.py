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

from ._base import Config


class RatelimitConfig(Config):

    def read_config(self, config):
        self.rc_messages_per_second = config.get("rc_messages_per_second", 0.2)
        self.rc_message_burst_count = config.get("rc_message_burst_count", 10.0)

        self.federation_rc_window_size = config.get("federation_rc_window_size", 1000)
        self.federation_rc_sleep_limit = config.get("federation_rc_sleep_limit", 10)
        self.federation_rc_sleep_delay = config.get("federation_rc_sleep_delay", 500)
        self.federation_rc_reject_limit = config.get("federation_rc_reject_limit", 50)
        self.federation_rc_concurrent = config.get("federation_rc_concurrent", 3)

        self.rc_registration_requests_per_second = config.get(
            "rc_registration_requests_per_second", 0.17,
        )
        self.rc_registration_request_burst_count = config.get(
            "rc_registration_request_burst_count", 3,
        )

    def default_config(self, **kwargs):
        return """\
        ## Ratelimiting ##

        # Number of messages a client can send per second
        #
        #rc_messages_per_second: 0.2

        # Number of message a client can send before being throttled
        #
        #rc_message_burst_count: 10.0

        # The federation window size in milliseconds
        #
        #federation_rc_window_size: 1000

        # The number of federation requests from a single server in a window
        # before the server will delay processing the request.
        #
        #federation_rc_sleep_limit: 10

        # The duration in milliseconds to delay processing events from
        # remote servers by if they go over the sleep limit.
        #
        #federation_rc_sleep_delay: 500

        # The maximum number of concurrent federation requests allowed
        # from a single server
        #
        #federation_rc_reject_limit: 50

        # The number of federation requests to concurrently process from a
        # single server
        #
        #federation_rc_concurrent: 3

        # Number of registration requests a client can send per second.
        # Defaults to 1/minute (0.17).
        #
        #rc_registration_requests_per_second: 0.17

        # Number of registration requests a client can send before being
        # throttled.
        # Defaults to 3.
        #
        #rc_registration_request_burst_count: 3.0
        """
