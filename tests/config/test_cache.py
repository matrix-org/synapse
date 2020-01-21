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

import os

from synapse.config._base import Config, RootConfig
from synapse.config.cache import CacheConfig

from tests.unittest import TestCase


class FakeServer(Config):
    section = "server"


class TestConfig(RootConfig):
    config_classes = [FakeServer, CacheConfig]


class CacheConfigTests(TestCase):
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
        Individual cache factors defined in config will take precedence over
        ones in the environment.
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
            {"foo": 2.0, "bar": 3.0, "something_or_other": 2.0},
        )
