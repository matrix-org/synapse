# Copyright 2022 The Matrix.org Foundation C.I.C.
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
import yaml

from synapse.storage.background_updates import BackgroundUpdater

from tests.unittest import HomeserverTestCase, override_config


class BackgroundUpdateConfigTestCase(HomeserverTestCase):
    # Tests that the default values in the config are correctly loaded. Note that the default
    # values are loaded when the corresponding config options are commented out, which is why there isn't
    # a config specified here.
    def test_default_configuration(self):
        background_updater = BackgroundUpdater(
            self.hs, self.hs.get_datastores().main.db_pool
        )

        self.assertEqual(background_updater.minimum_background_batch_size, 1)
        self.assertEqual(background_updater.default_background_batch_size, 100)
        self.assertEqual(background_updater.sleep_enabled, True)
        self.assertEqual(background_updater.sleep_duration_ms, 1000)
        self.assertEqual(background_updater.update_duration_ms, 100)

    # Tests that non-default values for the config options are properly picked up and passed on.
    @override_config(
        yaml.safe_load(
            """
            background_updates:
                background_update_duration_ms: 1000
                sleep_enabled: false
                sleep_duration_ms: 600
                min_batch_size: 5
                default_batch_size: 50
            """
        )
    )
    def test_custom_configuration(self):
        background_updater = BackgroundUpdater(
            self.hs, self.hs.get_datastores().main.db_pool
        )

        self.assertEqual(background_updater.minimum_background_batch_size, 5)
        self.assertEqual(background_updater.default_background_batch_size, 50)
        self.assertEqual(background_updater.sleep_enabled, False)
        self.assertEqual(background_updater.sleep_duration_ms, 600)
        self.assertEqual(background_updater.update_duration_ms, 1000)
