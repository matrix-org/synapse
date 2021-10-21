# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from synapse.config._base import ConfigError

if __name__ == "__main__":
    import sys

    from synapse.config.homeserver import HomeServerConfig

    action = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] == "read" else None
    load_config_args = sys.argv[3:] if action else sys.argv[1:]

    try:
        config = HomeServerConfig.load_config("", load_config_args)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    print("Config parses OK!")

    if action == "read":
        key = sys.argv[2]
        key_parts = key.split(".")

        value = config
        while len(key_parts):
            value = getattr(value, key_parts[0])
            key_parts.pop(0)

        print(f"{key}: {value}")
        sys.exit(0)
