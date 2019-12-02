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

import yaml

from synapse.config.room_directory import RoomDirectoryConfig

from tests import unittest


class RoomDirectoryConfigTestCase(unittest.TestCase):
    def test_alias_creation_acl(self):
        config = yaml.safe_load(
            """
        alias_creation_rules:
            - user_id: "*bob*"
              alias: "*"
              action: "deny"
            - user_id: "*"
              alias: "#unofficial_*"
              action: "allow"
            - user_id: "@foo*:example.com"
              alias: "*"
              action: "allow"
            - user_id: "@gah:example.com"
              alias: "#goo:example.com"
              action: "allow"

        room_list_publication_rules: []
        """
        )

        rd_config = RoomDirectoryConfig()
        rd_config.read_config(config)

        self.assertFalse(
            rd_config.is_alias_creation_allowed(
                user_id="@bob:example.com", room_id="!test", alias="#test:example.com"
            )
        )

        self.assertTrue(
            rd_config.is_alias_creation_allowed(
                user_id="@test:example.com",
                room_id="!test",
                alias="#unofficial_st:example.com",
            )
        )

        self.assertTrue(
            rd_config.is_alias_creation_allowed(
                user_id="@foobar:example.com",
                room_id="!test",
                alias="#test:example.com",
            )
        )

        self.assertTrue(
            rd_config.is_alias_creation_allowed(
                user_id="@gah:example.com", room_id="!test", alias="#goo:example.com"
            )
        )

        self.assertFalse(
            rd_config.is_alias_creation_allowed(
                user_id="@test:example.com", room_id="!test", alias="#test:example.com"
            )
        )

    def test_room_publish_acl(self):
        config = yaml.safe_load(
            """
        alias_creation_rules: []

        room_list_publication_rules:
            - user_id: "*bob*"
              alias: "*"
              action: "deny"
            - user_id: "*"
              alias: "#unofficial_*"
              action: "allow"
            - user_id: "@foo*:example.com"
              alias: "*"
              action: "allow"
            - user_id: "@gah:example.com"
              alias: "#goo:example.com"
              action: "allow"
            - room_id: "!test-deny"
              action: "deny"
        """
        )

        rd_config = RoomDirectoryConfig()
        rd_config.read_config(config)

        self.assertFalse(
            rd_config.is_publishing_room_allowed(
                user_id="@bob:example.com",
                room_id="!test",
                aliases=["#test:example.com"],
            )
        )

        self.assertTrue(
            rd_config.is_publishing_room_allowed(
                user_id="@test:example.com",
                room_id="!test",
                aliases=["#unofficial_st:example.com"],
            )
        )

        self.assertTrue(
            rd_config.is_publishing_room_allowed(
                user_id="@foobar:example.com", room_id="!test", aliases=[]
            )
        )

        self.assertTrue(
            rd_config.is_publishing_room_allowed(
                user_id="@gah:example.com",
                room_id="!test",
                aliases=["#goo:example.com"],
            )
        )

        self.assertFalse(
            rd_config.is_publishing_room_allowed(
                user_id="@test:example.com",
                room_id="!test",
                aliases=["#test:example.com"],
            )
        )

        self.assertTrue(
            rd_config.is_publishing_room_allowed(
                user_id="@foobar:example.com", room_id="!test-deny", aliases=[]
            )
        )

        self.assertFalse(
            rd_config.is_publishing_room_allowed(
                user_id="@gah:example.com", room_id="!test-deny", aliases=[]
            )
        )

        self.assertTrue(
            rd_config.is_publishing_room_allowed(
                user_id="@test:example.com",
                room_id="!test",
                aliases=["#unofficial_st:example.com", "#blah:example.com"],
            )
        )
