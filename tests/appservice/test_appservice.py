# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from twisted.internet import defer

from mock import Mock
from tests import unittest

import re


def _regex(regex, exclusive=True):
    return {
        "regex": re.compile(regex),
        "exclusive": exclusive
    }


class ApplicationServiceTestCase(unittest.TestCase):

    def setUp(self):
        self.service = ApplicationService(
            id="unique_identifier",
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

        self.store = Mock()

    @defer.inlineCallbacks
    def test_regex_user_id_prefix_match(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*")
        )
        self.event.sender = "@irc_foobar:matrix.org"
        self.assertTrue((yield self.service.is_interested(self.event)))

    @defer.inlineCallbacks
    def test_regex_user_id_prefix_no_match(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*")
        )
        self.event.sender = "@someone_else:matrix.org"
        self.assertFalse((yield self.service.is_interested(self.event)))

    @defer.inlineCallbacks
    def test_regex_room_member_is_checked(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*")
        )
        self.event.sender = "@someone_else:matrix.org"
        self.event.type = "m.room.member"
        self.event.state_key = "@irc_foobar:matrix.org"
        self.assertTrue((yield self.service.is_interested(self.event)))

    @defer.inlineCallbacks
    def test_regex_room_id_match(self):
        self.service.namespaces[ApplicationService.NS_ROOMS].append(
            _regex("!some_prefix.*some_suffix:matrix.org")
        )
        self.event.room_id = "!some_prefixs0m3th1nGsome_suffix:matrix.org"
        self.assertTrue((yield self.service.is_interested(self.event)))

    @defer.inlineCallbacks
    def test_regex_room_id_no_match(self):
        self.service.namespaces[ApplicationService.NS_ROOMS].append(
            _regex("!some_prefix.*some_suffix:matrix.org")
        )
        self.event.room_id = "!XqBunHwQIXUiqCaoxq:matrix.org"
        self.assertFalse((yield self.service.is_interested(self.event)))

    @defer.inlineCallbacks
    def test_regex_alias_match(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            _regex("#irc_.*:matrix.org")
        )
        self.store.get_aliases_for_room.return_value = [
            "#irc_foobar:matrix.org", "#athing:matrix.org"
        ]
        self.store.get_users_in_room.return_value = []
        self.assertTrue((yield self.service.is_interested(
            self.event, self.store
        )))

    def test_non_exclusive_alias(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            _regex("#irc_.*:matrix.org", exclusive=False)
        )
        self.assertFalse(self.service.is_exclusive_alias(
            "#irc_foobar:matrix.org"
        ))

    def test_non_exclusive_room(self):
        self.service.namespaces[ApplicationService.NS_ROOMS].append(
            _regex("!irc_.*:matrix.org", exclusive=False)
        )
        self.assertFalse(self.service.is_exclusive_room(
            "!irc_foobar:matrix.org"
        ))

    def test_non_exclusive_user(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*:matrix.org", exclusive=False)
        )
        self.assertFalse(self.service.is_exclusive_user(
            "@irc_foobar:matrix.org"
        ))

    def test_exclusive_alias(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            _regex("#irc_.*:matrix.org", exclusive=True)
        )
        self.assertTrue(self.service.is_exclusive_alias(
            "#irc_foobar:matrix.org"
        ))

    def test_exclusive_user(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*:matrix.org", exclusive=True)
        )
        self.assertTrue(self.service.is_exclusive_user(
            "@irc_foobar:matrix.org"
        ))

    def test_exclusive_room(self):
        self.service.namespaces[ApplicationService.NS_ROOMS].append(
            _regex("!irc_.*:matrix.org", exclusive=True)
        )
        self.assertTrue(self.service.is_exclusive_room(
            "!irc_foobar:matrix.org"
        ))

    @defer.inlineCallbacks
    def test_regex_alias_no_match(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            _regex("#irc_.*:matrix.org")
        )
        self.store.get_aliases_for_room.return_value = [
            "#xmpp_foobar:matrix.org", "#athing:matrix.org"
        ]
        self.store.get_users_in_room.return_value = []
        self.assertFalse((yield self.service.is_interested(
            self.event, self.store
        )))

    @defer.inlineCallbacks
    def test_regex_multiple_matches(self):
        self.service.namespaces[ApplicationService.NS_ALIASES].append(
            _regex("#irc_.*:matrix.org")
        )
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*")
        )
        self.event.sender = "@irc_foobar:matrix.org"
        self.store.get_aliases_for_room.return_value = ["#irc_barfoo:matrix.org"]
        self.store.get_users_in_room.return_value = []
        self.assertTrue((yield self.service.is_interested(
            self.event, self.store
        )))

    @defer.inlineCallbacks
    def test_interested_in_self(self):
        # make sure invites get through
        self.service.sender = "@appservice:name"
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*")
        )
        self.event.type = "m.room.member"
        self.event.content = {
            "membership": "invite"
        }
        self.event.state_key = self.service.sender
        self.assertTrue((yield self.service.is_interested(self.event)))

    @defer.inlineCallbacks
    def test_member_list_match(self):
        self.service.namespaces[ApplicationService.NS_USERS].append(
            _regex("@irc_.*")
        )
        self.store.get_users_in_room.return_value = [
            "@alice:here",
            "@irc_fo:here",  # AS user
            "@bob:here",
        ]
        self.store.get_aliases_for_room.return_value = []

        self.event.sender = "@xmpp_foobar:matrix.org"
        self.assertTrue((yield self.service.is_interested(
            event=self.event, store=self.store
        )))
