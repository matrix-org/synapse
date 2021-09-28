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

from synapse.config._base import Config
from synapse.python_dependencies import check_requirements


class RedisConfig(Config):
    section = "redis"

    def read_config(self, config, **kwargs):
        redis_config = config.get("redis") or {}
        self.redis_enabled = redis_config.get("enabled", False)

        if not self.redis_enabled:
            return

        check_requirements("redis")

        self.redis_host = redis_config.get("host", "localhost")
        self.redis_port = redis_config.get("port", 6379)
        self.redis_password = redis_config.get("password")

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        # Configuration for Redis when using workers. This *must* be enabled when
        # using workers (unless using old style direct TCP configuration).
        #
        redis:
          # Uncomment the below to enable Redis support.
          #
          #enabled: true

          # Optional host and port to use to connect to redis. Defaults to
          # localhost and 6379
          #
          #host: localhost
          #port: 6379

          # Optional password if configured on the Redis instance
          #
          #password: <secret_password>
        """
