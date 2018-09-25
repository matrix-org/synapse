# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
    from homeserver import HomeServerConfig

    action = sys.argv[1]

    if action == "read":
        key = sys.argv[2]
        try:
            config = HomeServerConfig.load_config("", sys.argv[3:])
        except ConfigError as e:
            sys.stderr.write("\n" + str(e) + "\n")
            sys.exit(1)

        print (getattr(config, key))
        sys.exit(0)
    else:
        sys.stderr.write("Unknown command %r\n" % (action,))
        sys.exit(1)
