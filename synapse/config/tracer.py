# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.d
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

from ._base import Config, ConfigError


class TracerConfig(Config):
    def read_config(self, config, **kwargs):
        opentracing_config = config.get("opentracing")
        if opentracing_config is None:
            opentracing_config = {}

        self.opentracer_enabled = opentracing_config.get("enabled", False)
        if not self.opentracer_enabled:
            return

        # The tracer is enabled so sanitize the config

        self.opentracer_whitelist = opentracing_config.get("homeserver_whitelist", [])
        if not isinstance(self.opentracer_whitelist, list):
            raise ConfigError("Tracer homeserver_whitelist config is malformed")

    def generate_config_section(cls, **kwargs):
        return """\
        ## Opentracing ##

        # These settings enable opentracing, which implements distributed tracing.
        # This allows you to observe the causal chains of events across servers
        # including requests, key lookups etc., across any server running
        # synapse or any other other services which supports opentracing
        # (specifically those implemented with Jaeger).
        #
        opentracing:
            # tracing is disabled by default. Uncomment the following line to enable it.
            #
            #enabled: true

            # The list of homeservers we wish to send and receive span contexts and span baggage.
            # See docs/opentracing.rst
            # This is a list of regexes which are matched against the server_name of the
            # homeserver.
            #
            # By defult, it is empty, so no servers are matched.
            #
            #homeserver_whitelist:
            #  - ".*"
        """
