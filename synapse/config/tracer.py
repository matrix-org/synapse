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

from typing import Set

from synapse.python_dependencies import DependencyException, check_requirements

from ._base import Config, ConfigError


class TracerConfig(Config):
    section = "tracing"

    def read_config(self, config, **kwargs):
        opentracing_config = config.get("opentracing")
        if opentracing_config is None:
            opentracing_config = {}

        self.opentracer_enabled = opentracing_config.get("enabled", False)

        self.jaeger_config = opentracing_config.get(
            "jaeger_config",
            {"sampler": {"type": "const", "param": 1}, "logging": False},
        )

        self.force_tracing_for_users: Set[str] = set()

        if not self.opentracer_enabled:
            return

        try:
            check_requirements("opentracing")
        except DependencyException as e:
            raise ConfigError(
                e.message  # noqa: B306, DependencyException.message is a property
            )

        # The tracer is enabled so sanitize the config

        self.opentracer_whitelist = opentracing_config.get("homeserver_whitelist", [])
        if not isinstance(self.opentracer_whitelist, list):
            raise ConfigError("Tracer homeserver_whitelist config is malformed")

        force_tracing_for_users = opentracing_config.get("force_tracing_for_users", [])
        if not isinstance(force_tracing_for_users, list):
            raise ConfigError(
                "Expected a list", ("opentracing", "force_tracing_for_users")
            )
        for i, u in enumerate(force_tracing_for_users):
            if not isinstance(u, str):
                raise ConfigError(
                    "Expected a string",
                    ("opentracing", "force_tracing_for_users", f"index {i}"),
                )
            self.force_tracing_for_users.add(u)

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
            # See docs/opentracing.rst.
            #
            # This is a list of regexes which are matched against the server_name of the
            # homeserver.
            #
            # By default, it is empty, so no servers are matched.
            #
            #homeserver_whitelist:
            #  - ".*"

            # A list of the matrix IDs of users whose requests will always be traced,
            # even if the tracing system would otherwise drop the traces due to
            # probabilistic sampling.
            #
            # By default, the list is empty.
            #
            #force_tracing_for_users:
            #  - "@user1:server_name"
            #  - "@user2:server_name"

            # Jaeger can be configured to sample traces at different rates.
            # All configuration options provided by Jaeger can be set here.
            # Jaeger's configuration is mostly related to trace sampling which
            # is documented here:
            # https://www.jaegertracing.io/docs/latest/sampling/.
            #
            #jaeger_config:
            #  sampler:
            #    type: const
            #    param: 1
            #  logging:
            #    false
        """
