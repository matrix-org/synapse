# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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
from synapse.rulecheck.domain_rule_checker import DomainRuleChecker

from tests import unittest


class DomainRuleCheckerTestCase(unittest.TestCase):
    def test_allowed(self):
        config = {
            "default": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        check = DomainRuleChecker(config)
        self.assertTrue(
            check.user_may_invite("test:source_one", "test:target_one", "room", False)
        )
        self.assertTrue(
            check.user_may_invite("test:source_one", "test:target_two", "room", False)
        )
        self.assertTrue(
            check.user_may_invite("test:source_two", "test:target_two", "room", False)
        )

    def test_disallowed(self):
        config = {
            "default": True,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
                "source_four": [],
            },
        }
        check = DomainRuleChecker(config)
        self.assertFalse(
            check.user_may_invite("test:source_one", "test:target_three", "room", False)
        )
        self.assertFalse(
            check.user_may_invite("test:source_two", "test:target_three", "room", False)
        )
        self.assertFalse(
            check.user_may_invite("test:source_two", "test:target_one", "room", False)
        )
        self.assertFalse(
            check.user_may_invite("test:source_four", "test:target_one", "room", False)
        )

    def test_default_allow(self):
        config = {
            "default": True,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        check = DomainRuleChecker(config)
        self.assertTrue(
            check.user_may_invite("test:source_three", "test:target_one", "room", False)
        )

    def test_default_deny(self):
        config = {
            "default": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        check = DomainRuleChecker(config)
        self.assertFalse(
            check.user_may_invite("test:source_three", "test:target_one", "room", False)
        )

    def test_config_parse(self):
        config = {
            "default": False,
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            },
        }
        self.assertEquals(config, DomainRuleChecker.parse_config(config))

    def test_config_parse_failure(self):
        config = {
            "domain_mapping": {
                "source_one": ["target_one", "target_two"],
                "source_two": ["target_two"],
            }
        }
        self.assertRaises(ConfigError, DomainRuleChecker.parse_config, config)
