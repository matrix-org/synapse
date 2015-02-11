# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
from synapse.appservice import ApplicationService

from mock import Mock, PropertyMock
from tests import unittest


class ApplicationServiceTestCase(unittest.TestCase):

    def setUp(self):
        self.service = ApplicationService(
            url="some_url",
            token="some_token",
            namespaces={
                ApplicationService.NS_USERS: [],
                ApplicationService.NS_ROOMS: [],
                ApplicationService.NS_ALIASES: []
            }
        )
        self.event = Mock(
            type="m.something", room_id="!foo:bar", sender="@someone:somewhere"
        )

    def test_regex_user_id_prefix_match(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        self.event.sender = "@irc_foobar:matrix.org"
        self.assertTrue(self.service.is_interested(self.event))

    def test_regex_user_id_prefix_no_match(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        self.event.sender = "@someone_else:matrix.org"
        self.assertFalse(self.service.is_interested(self.event))

    def test_regex_room_member_is_checked(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        self.event.sender = "@someone_else:matrix.org"
        self.event.type = "m.room.member"
        self.event.state_key = "@irc_foobar:matrix.org"
        self.assertTrue(self.service.is_interested(self.event))

    def test_regex_room_id_match(self):
        self.service.namespaces[ApplicationService.NS_ROOMS].append(
            "!some_prefix.*some_suffix:matrix.org"
        )
        self.event.room_id = "!some_prefixs0m3th1nGsome_suffix:matrix.org"
        self.assertTrue(self.service.is_interested(self.event))

    def test_regex_room_id_no_match(self):
        self.service.namespaces[ApplicationService.NS_ROOMS].append(
            "!some_prefix.*some_suffix:matrix.org"
        )
        self.event.room_id = "!XqBunHwQIXUiqCaoxq:matrix.org"
        self.assertFalse(self.service.is_interested(self.event))

    def test_regex_alias_match(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            "#irc_.*:matrix.org"
        )
        self.assertTrue(self.service.is_interested(
            self.event,
            aliases_for_event=["#irc_foobar:matrix.org", "#athing:matrix.org"]
        ))

    def test_regex_alias_no_match(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            "#irc_.*:matrix.org"
        )
        self.assertFalse(self.service.is_interested(
            self.event,
            aliases_for_event=["#xmpp_foobar:matrix.org", "#athing:matrix.org"]
        ))

    def test_regex_multiple_matches(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            "#irc_.*:matrix.org"
        )
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        self.event.sender = "@irc_foobar:matrix.org"
        self.assertTrue(self.service.is_interested(
            self.event,
            aliases_for_event=["#irc_barfoo:matrix.org"]
        ))

    def test_restrict_to_rooms(self):
        self.service.namespaces[ApplicationService.NS_ROOMS].append(
            "!flibble_.*:matrix.org"
        )
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        self.event.sender = "@irc_foobar:matrix.org"
        self.event.room_id = "!wibblewoo:matrix.org"
        self.assertFalse(self.service.is_interested(
            self.event,
            restrict_to=ApplicationService.NS_ROOMS
        ))

    def test_restrict_to_aliases(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            "#xmpp_.*:matrix.org"
        )
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        self.event.sender = "@irc_foobar:matrix.org"
        self.assertFalse(self.service.is_interested(
            self.event,
            restrict_to=ApplicationService.NS_ALIASES,
            aliases_for_event=["#irc_barfoo:matrix.org"]
        ))

    def test_restrict_to_senders(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            "#xmpp_.*:matrix.org"
        )
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        self.event.sender = "@xmpp_foobar:matrix.org"
        self.assertFalse(self.service.is_interested(
            self.event,
            restrict_to=ApplicationService.NS_USERS,
            aliases_for_event=["#xmpp_barfoo:matrix.org"]
        ))

    def test_member_list_match(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            "@irc_.*"
        )
        join_list = [
            Mock(
                type="m.room.member", room_id="!foo:bar", sender="@alice:here",
                state_key="@alice:here"
            ),
            Mock(
                type="m.room.member", room_id="!foo:bar", sender="@irc_fo:here",
                state_key="@irc_fo:here"  # AS user
            ),
            Mock(
                type="m.room.member", room_id="!foo:bar", sender="@bob:here",
                state_key="@bob:here"
            )
        ]

        self.event.sender = "@xmpp_foobar:matrix.org"
        self.assertTrue(self.service.is_interested(
            event=self.event,
            member_list=join_list
        ))
