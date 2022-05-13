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
from synapse.config.__main__ import main

from tests.config.utils import ConfigFileTestCase


class ConfigMainFileTestCase(ConfigFileTestCase):
    def test_executes_without_an_action(self):
        self.generate_config()
        main(["", "-c", self.config_file])

    def test_read__error_if_key_not_found(self):
        self.generate_config()
        with self.assertRaises(SystemExit):
            main(["", "read", "foo.bar.hello", "-c", self.config_file])

    def test_read__passes_if_key_found(self):
        self.generate_config()
        main(["", "read", "server.server_name", "-c", self.config_file])
