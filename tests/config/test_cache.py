# -*- coding: utf-8 -*-
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

from synapse.config._base import Config, RootConfig
from synapse.config.cache import CacheConfig, add_resizable_cache
from synapse.util.caches.lrucache import LruCache

from tests.unittest import TestCase


class FakeServer(Config):
    section = "server"


class TestConfig(RootConfig):
    config_classes = [FakeServer, CacheConfig]


class CacheConfigTests(TestCase):
    def setUp(self):
        # Reset caches before each test
        TestConfig().caches.reset()

    def test_individual_caches_from_environ(self):
        """
        Individual cache factors will be loaded from the environment.
        """
        config = {}
        t = TestConfig()
        t.caches._environ = {
            "SYNAPSE_CACHE_FACTOR_SOMETHING_OR_OTHER": "2",
            "SYNAPSE_NOT_CACHE": "BLAH",
        }
        t.read_config(config, config_dir_path="", data_dir_path="")

        self.assertEqual(dict(t.caches.cache_factors), {"something_or_other": 2.0})

    def test_config_overrides_environ(self):
        """
        Individual cache factors defined in the environment will take precedence
        over those in the config.
        """
        config = {"caches": {"per_cache_factors": {"foo": 2, "bar": 3}}}
        t = TestConfig()
        t.caches._environ = {
            "SYNAPSE_CACHE_FACTOR_SOMETHING_OR_OTHER": "2",
            "SYNAPSE_CACHE_FACTOR_FOO": 1,
        }
        t.read_config(config, config_dir_path="", data_dir_path="")

        self.assertEqual(
            dict(t.caches.cache_factors),
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
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")

        self.assertEqual(cache.max_size, 300)

    def test_individual_instantiated_after_config_load(self):
        """
        If a cache is instantiated after the config is read, it will be
        immediately resized to the correct size given the per_cache_factor if
        there is one.
        """
        config = {"caches": {"per_cache_factors": {"foo": 2}}}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")

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
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")

        self.assertEqual(cache.max_size, 400)

    def test_global_instantiated_after_config_load(self):
        """
        If a cache is instantiated after the config is read, it will be
        immediately resized to the correct size given the global factor if there
        is no per-cache factor.
        """
        config = {"caches": {"global_factor": 1.5}}
        t = TestConfig()
        t.read_config(config, config_dir_path="", data_dir_path="")

        cache = LruCache(100)
        add_resizable_cache("foo", cache_resize_callback=cache.set_cache_factor)
        self.assertEqual(cache.max_size, 150)
