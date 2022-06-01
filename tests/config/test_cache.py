# Copyright 2020 Matrix.org Foundation C.I.C.
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

from synapse.config.cache import CacheConfig, add_resizable_cache
from synapse.util.caches.lrucache import LruCache

from tests.unittest import TestCase


class CacheConfigTests(TestCase):
    def setUp(self):
        # Reset caches before each test since there's global state involved.
        self.config = CacheConfig()
        self.config.reset()

    def tearDown(self):
        # Also reset the caches after each test to leave state pristine.
        self.config.reset()

    def test_individual_caches_from_environ(self):
        """
        Individual cache factors will be loaded from the environment.
        """
        config = {}
        self.config._environ = {
            "SYNAPSE_CACHE_FACTOR_SOMETHING_OR_OTHER": "2",
            "SYNAPSE_NOT_CACHE": "BLAH",
        }
        self.config.read_config(config, config_dir_path="", data_dir_path="")
        self.config.resize_all_caches()

        self.assertEqual(dict(self.config.cache_factors), {"something_or_other": 2.0})

    def test_config_overrides_environ(self):
        """
        Individual cache factors defined in the environment will take precedence
        over those in the config.
        """
        config = {"caches": {"per_cache_factors": {"foo": 2, "bar": 3}}}
        self.config._environ = {
            "SYNAPSE_CACHE_FACTOR_SOMETHING_OR_OTHER": "2",
            "SYNAPSE_CACHE_FACTOR_FOO": 1,
        }
        self.config.read_config(config, config_dir_path="", data_dir_path="")
        self.config.resize_all_caches()

        self.assertEqual(
            dict(self.config.cache_factors),
            {"foo": 1.0, "bar": 3.0, "something_or_other": 2.0},
        )

    def test_individual_instantiated_before_config_load(self):
        """
        If a cache is instantiated before the config is read, it will be given
        the default cache size in the interim, and then resized once the config
        is loaded.
        """
        cache = LruCache(100)

        add_resizable_cache("foo", cache_resize_callback=cache.set_cache_factor)
        self.assertEqual(cache.max_size, 50)

        config = {"caches": {"per_cache_factors": {"foo": 3}}}
        self.config.read_config(config)
        self.config.resize_all_caches()

        self.assertEqual(cache.max_size, 300)

    def test_individual_instantiated_after_config_load(self):
        """
        If a cache is instantiated after the config is read, it will be
        immediately resized to the correct size given the per_cache_factor if
        there is one.
        """
        config = {"caches": {"per_cache_factors": {"foo": 2}}}
        self.config.read_config(config, config_dir_path="", data_dir_path="")
        self.config.resize_all_caches()

        cache = LruCache(100)
        add_resizable_cache("foo", cache_resize_callback=cache.set_cache_factor)
        self.assertEqual(cache.max_size, 200)

    def test_global_instantiated_before_config_load(self):
        """
        If a cache is instantiated before the config is read, it will be given
        the default cache size in the interim, and then resized to the new
        default cache size once the config is loaded.
        """
        cache = LruCache(100)
        add_resizable_cache("foo", cache_resize_callback=cache.set_cache_factor)
        self.assertEqual(cache.max_size, 50)

        config = {"caches": {"global_factor": 4}}
        self.config.read_config(config, config_dir_path="", data_dir_path="")
        self.config.resize_all_caches()

        self.assertEqual(cache.max_size, 400)

    def test_global_instantiated_after_config_load(self):
        """
        If a cache is instantiated after the config is read, it will be
        immediately resized to the correct size given the global factor if there
        is no per-cache factor.
        """
        config = {"caches": {"global_factor": 1.5}}
        self.config.read_config(config, config_dir_path="", data_dir_path="")
        self.config.resize_all_caches()

        cache = LruCache(100)
        add_resizable_cache("foo", cache_resize_callback=cache.set_cache_factor)
        self.assertEqual(cache.max_size, 150)

    def test_cache_with_asterisk_in_name(self):
        """Some caches have asterisks in their name, test that they are set correctly."""

        config = {
            "caches": {
                "per_cache_factors": {"*cache_a*": 5, "cache_b": 6, "cache_c": 2}
            }
        }
        self.config._environ = {
            "SYNAPSE_CACHE_FACTOR_CACHE_A": "2",
            "SYNAPSE_CACHE_FACTOR_CACHE_B": 3,
        }
        self.config.read_config(config, config_dir_path="", data_dir_path="")
        self.config.resize_all_caches()

        cache_a = LruCache(100)
        add_resizable_cache("*cache_a*", cache_resize_callback=cache_a.set_cache_factor)
        self.assertEqual(cache_a.max_size, 200)

        cache_b = LruCache(100)
        add_resizable_cache("*Cache_b*", cache_resize_callback=cache_b.set_cache_factor)
        self.assertEqual(cache_b.max_size, 300)

        cache_c = LruCache(100)
        add_resizable_cache("*cache_c*", cache_resize_callback=cache_c.set_cache_factor)
        self.assertEqual(cache_c.max_size, 200)

    def test_apply_cache_factor_from_config(self):
        """Caches can disable applying cache factor updates, mainly used by
        event cache size.
        """

        config = {"caches": {"event_cache_size": "10k"}}
        self.config.read_config(config, config_dir_path="", data_dir_path="")
        self.config.resize_all_caches()

        cache = LruCache(
            max_size=self.config.event_cache_size,
            apply_cache_factor_from_config=False,
        )
        add_resizable_cache("event_cache", cache_resize_callback=cache.set_cache_factor)

        self.assertEqual(cache.max_size, 10240)
