# -*- coding: utf-8 -*-
# Copyright 2018 New Vector
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
from mock import Mock

from twisted.internet import defer

from synapse.api.constants import UserTypes
from synapse.handlers.user_directory import UserDirectoryHandler
from synapse.storage.roommember import ProfileInfo

from tests import unittest
from tests.utils import setup_test_homeserver


class UserDirectoryHandlers(object):
    def __init__(self, hs):
        self.user_directory_handler = UserDirectoryHandler(hs)


class UserDirectoryTestCase(unittest.TestCase):
    """ Tests the UserDirectoryHandler. """

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(self.addCleanup)
        self.store = hs.get_datastore()
        hs.handlers = UserDirectoryHandlers(hs)

        self.handler = hs.get_handlers().user_directory_handler

    @defer.inlineCallbacks
    def test_handle_local_profile_change_with_support_user(self):
        support_user_id = "@support:test"
        yield self.store.register(
            user_id=support_user_id,
            token="123",
            password_hash=None,
            user_type=UserTypes.SUPPORT
        )

        yield self.handler.handle_local_profile_change(support_user_id, None)
        profile = yield self.store.get_user_in_directory(support_user_id)
        self.assertTrue(profile is None)
        display_name = 'display_name'

        profile_info = ProfileInfo(
            avatar_url='avatar_url',
            display_name=display_name,
        )
        regular_user_id = '@regular:test'
        yield self.handler.handle_local_profile_change(regular_user_id, profile_info)
        profile = yield self.store.get_user_in_directory(regular_user_id)
        self.assertTrue(profile['display_name'] == display_name)

    @defer.inlineCallbacks
    def test_handle_user_deactivated_support_user(self):
        s_user_id = "@support:test"
        self.store.register(
            user_id=s_user_id,
            token="123",
            password_hash=None,
            user_type=UserTypes.SUPPORT
        )

        self.store.remove_from_user_dir = Mock()
        self.store.remove_from_user_in_public_room = Mock()
        yield self.handler.handle_user_deactivated(s_user_id)
        self.store.remove_from_user_dir.not_called()
        self.store.remove_from_user_in_public_room.not_called()

    @defer.inlineCallbacks
    def test_handle_user_deactivated_regular_user(self):
        r_user_id = "@regular:test"
        self.store.register(user_id=r_user_id, token="123", password_hash=None)
        self.store.remove_from_user_dir = Mock()
        self.store.remove_from_user_in_public_room = Mock()
        yield self.handler.handle_user_deactivated(r_user_id)
        self.store.remove_from_user_dir.called_once_with(r_user_id)
        self.store.remove_from_user_in_public_room.assert_called_once_with(r_user_id)
