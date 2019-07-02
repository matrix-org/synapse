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
        self.tracer_config = config.get("opentracing")

        self.tracer_config = config.get("opentracing", {"tracer_enabled": False})

        if self.tracer_config.get("tracer_enabled", False):
            # The tracer is enabled so sanitize the config
            # If no whitelists are given
            self.tracer_config.setdefault("homeserver_whitelist", [])

            if not isinstance(self.tracer_config.get("homeserver_whitelist"), list):
                raise ConfigError("Tracer homesererver_whitelist config is malformed")

    def generate_config_section(cls, **kwargs):
        return """\
        ## Opentracing ##
        # These settings enable opentracing which implements distributed tracing
        # This allows you to observe the causal chain of events across servers
        # including requests, key lookups etc. across any server running
        # synapse or any other other services which supports opentracing.
        # (specifically those implemented with jaeger)

        #opentracing:
        #  # Enable / disable tracer
        #  tracer_enabled: false
        #  # The list of homeservers we wish to expose our current traces to.
        #  # The list is a list of regexes which are matched against the
        #  # servername of the homeserver
        #  homeserver_whitelist:
        #    - ".*"
        """
