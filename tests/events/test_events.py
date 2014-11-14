# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.api.events import SynapseEvent
from synapse.api.events.validator import EventValidator
from synapse.api.errors import SynapseError

from tests import unittest


class SynapseTemplateCheckTestCase(unittest.TestCase):

    def setUp(self):
        self.validator = EventValidator(None)

    def tearDown(self):
        pass

    def test_top_level_keys(self):
        template = {
            "person": {},
            "friends": ["string"]
        }

        content = {
            "person": {"name": "bob"},
            "friends": ["jill", "mike"]
        }

        event = MockSynapseEvent(template)
        event.content = content
        self.assertTrue(self.validator.validate(event))

        content = {
            "person": {"name": "bob"},
            "friends": ["jill"],
            "enemies": ["mike"]
        }
        event.content = content
        self.assertTrue(self.validator.validate(event))

        content = {
            "person": {"name": "bob"},
            # missing friends
            "enemies": ["mike", "jill"]
        }
        event.content = content
        self.assertRaises(
            SynapseError,
            self.validator.validate,
            event
        )

    def test_lists(self):
        template = {
            "person": {},
            "friends": [{"name":"string"}]
        }

        content = {
            "person": {"name": "bob"},
            "friends": ["jill", "mike"]  # should be in objects
        }

        event = MockSynapseEvent(template)
        event.content = content
        self.assertRaises(
            SynapseError,
            self.validator.validate,
            event
        )

        content = {
            "person": {"name": "bob"},
            "friends": [{"name": "jill"}, {"name": "mike"}]
        }
        event.content = content
        self.assertTrue(self.validator.validate(event))

    def test_nested_lists(self):
        template = {
            "results": {
                "families": [
                     {
                        "name": "string",
                        "members": [
                            {}
                        ]
                     }
                ]
            }
        }

        content = {
            "results": {
                "families": [
                     {
                        "name": "Smith",
                        "members": [
                            "Alice", "Bob"  # wrong types
                        ]
                     }
                ]
            }
        }

        event = MockSynapseEvent(template)
        event.content = content
        self.assertRaises(
            SynapseError,
            self.validator.validate,
            event
        )

        content = {
            "results": {
                "families": [
                     {
                        "name": "Smith",
                        "members": [
                            {"name": "Alice"}, {"name": "Bob"}
                        ]
                     }
                ]
            }
        }
        event.content = content
        self.assertTrue(self.validator.validate(event))

    def test_nested_keys(self):
        template = {
            "person": {
                "attributes": {
                    "hair": "string",
                    "eye": "string"
                },
                "age": 0,
                "fav_books": ["string"]
            }
        }
        event = MockSynapseEvent(template)

        content = {
            "person": {
                "attributes": {
                    "hair": "brown",
                    "eye": "green",
                    "skin": "purple"
                },
                "age": 33,
                "fav_books": ["lotr", "hobbit"],
                "fav_music": ["abba", "beatles"]
            }
        }

        event.content = content
        self.assertTrue(self.validator.validate(event))

        content = {
            "person": {
                "attributes": {
                    "hair": "brown"
                    # missing eye
                },
                "age": 33,
                "fav_books": ["lotr", "hobbit"],
                "fav_music": ["abba", "beatles"]
            }
        }

        event.content = content
        self.assertRaises(
            SynapseError,
            self.validator.validate,
            event
        )

        content = {
            "person": {
                "attributes": {
                    "hair": "brown",
                    "eye": "green",
                    "skin": "purple"
                },
                "age": 33,
                "fav_books": "nothing",  # should be a list
            }
        }

        event.content = content
        self.assertRaises(
            SynapseError,
            self.validator.validate,
            event
        )


class MockSynapseEvent(SynapseEvent):

    def __init__(self, template):
        self.template = template

    def get_content_template(self):
        return self.template

