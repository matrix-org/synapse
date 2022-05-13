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

import synapse.app.homeserver
from synapse.config._base import ConfigError

from tests.config.utils import ConfigFileTestCase


class HomeserverAppStartTestCase(ConfigFileTestCase):
    def test_wrong_start_caught(self):
        # Generate a config with a worker_app
        self.generate_config()
        # Add a blank line as otherwise the next addition ends up on a line with a comment
        self.add_lines_to_config(["  "])
        self.add_lines_to_config(["worker_app: test_worker_app"])

        # Ensure that starting master process with worker config raises an exception
        with self.assertRaises(ConfigError):
            synapse.app.homeserver.setup(["-c", self.config_file])
