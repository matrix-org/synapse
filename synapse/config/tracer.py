# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

import logging

from jaeger_client import Config as JaegerConfig

from synapse.util.scopecontextmanager import LogContextScopeManager

from ._base import Config

logger = logging.getLogger(__name__)


class TracerConfig(Config):
    def read_config(self, config, **kwargs):
        self.tracer_config = config.get("tracer")

        if self.tracer_config is None:
            # If the tracer is not configured we assume it is disabled
            self.tracer_config = {"tracer_enabled": False}

        if self.tracer_config.get("tracer_enabled", False):
            # The tracer is enabled so sanitize the config
            # If no whitelists are given
            self.tracer_config.setdefault("user_whitelist", ["*"])
            self.tracer_config.setdefault("homeserver_whitelist", ["*"])

            if type(self.tracer_config.get("user_whitelist")) != list:
                raise RuntimeError("Tracer user_whitelist config is malformed")
            if type(self.tracer_config.get("homeserver_whitelist")) != list:
                raise RuntimeError("Tracer homesererver_whitelist config is malformed")

    def generate_config_section(cls, **kwargs):
        return """\
        ## Tracer ##

        #tracer:
        #  # Enable / disable tracer
        #  tracer_enabled: false
        #  # The list of users who's requests will be traced
        #  # The list is a list of regex which is matched against the user_id
        #  user_whitelist:
        #    - "*"
        #  # The list of homeservers we wish to trace across
        #  # The list is a list of regex which is matched against the homeserver name
        #  homeserver_whitelist:
        #    - "*"
        """


def init_tracing(config):
    """Initialise the JaegerClient tracer

    Args:
        config (Config)
        The config used by the homserver. Here it's used to set the service
        name to the homeserver's.
    """

    if config.tracer_config.get("tracer_enabled", False):
        jaeger_config = JaegerConfig(
            config={"sampler": {"type": "const", "param": 1}, "logging": True},
            service_name=config.server_name,
            scope_manager=LogContextScopeManager(config),
        )
    else:  # The tracer is not configured so we instantiate a noop tracer
        jaeger_config = JaegerConfig(
            config={"sampler": {"type": "const", "param": 0}},
            service_name=config.server_name,
        )

    return jaeger_config.initialize_tracer()
