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

from mock import Mock

from twisted.internet import defer

from synapse.api.constants import UserTypes
from synapse.api.errors import ResourceLimitError, SynapseError
from synapse.handlers.register import RegistrationHandler
from synapse.types import RoomAlias, UserID, create_requester

from .. import unittest


class RegistrationHandlers(object):
    def __init__(self, hs):
        self.registration_handler = RegistrationHandler(hs)


class RegistrationTestCase(unittest.HomeserverTestCase):
    """ Tests the RegistrationHandler. """

    def make_homeserver(self, reactor, clock):
        hs_config = self.default_config("test")

        # some of the tests rely on us having a user consent version
        hs_config["user_consent"] = {
            "version": "test_consent_version",
            "template_dir": ".",
        }
        hs_config["max_mau_value"] = 50
        hs_config["limit_usage_by_mau"] = True

        hs = self.setup_test_homeserver(config=hs_config, expire_access_token=True)
        return hs

    def prepare(self, reactor, clock, hs):
        self.mock_distributor = Mock()
        self.mock_distributor.declare("registered_user")
        self.mock_captcha_client = Mock()
        self.macaroon_generator = Mock(
            generate_access_token=Mock(return_value="secret")
        )
        self.hs.get_macaroon_generator = Mock(return_value=self.macaroon_generator)
        self.handler = self.hs.get_registration_handler()
        self.store = self.hs.get_datastore()
        self.lots_of_users = 100
        self.small_number_of_users = 1

        self.requester = create_requester("@requester:test")

    def test_user_is_created_and_logged_in_if_doesnt_exist(self):
        frank = UserID.from_string("@frank:test")
        user_id = frank.to_string()
        requester = create_requester(user_id)
        result_user_id, result_token = self.get_success(
            self.handler.get_or_create_user(requester, frank.localpart, "Frankie")
        )
        self.assertEquals(result_user_id, user_id)
        self.assertTrue(result_token is not None)
        self.assertEquals(result_token, "secret")

    def test_if_user_exists(self):
        store = self.hs.get_datastore()
        frank = UserID.from_string("@frank:test")
        self.get_success(
            store.register(
                user_id=frank.to_string(),
                token="jkv;g498752-43gj['eamb!-5",
                password_hash=None,
            )
        )
        local_part = frank.localpart
        user_id = frank.to_string()
        requester = create_requester(user_id)
        result_user_id, result_token = self.get_success(
            self.handler.get_or_create_user(requester, local_part, None)
        )
        self.assertEquals(result_user_id, user_id)
        self.assertTrue(result_token is not None)

    def test_mau_limits_when_disabled(self):
        self.hs.config.limit_usage_by_mau = False
        # Ensure does not throw exception
        self.get_success(
            self.handler.get_or_create_user(self.requester, "a", "display_name")
        )

    def test_get_or_create_user_mau_not_blocked(self):
        self.hs.config.limit_usage_by_mau = True
        self.store.count_monthly_users = Mock(
            return_value=defer.succeed(self.hs.config.max_mau_value - 1)
        )
        # Ensure does not throw exception
        self.get_success(self.handler.get_or_create_user(self.requester, "c", "User"))

    def test_get_or_create_user_mau_blocked(self):
        self.hs.config.limit_usage_by_mau = True
        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(self.lots_of_users)
        )
        self.get_failure(
            self.handler.get_or_create_user(self.requester, "b", "display_name"),
            ResourceLimitError,
        )

        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(self.hs.config.max_mau_value)
        )
        self.get_failure(
            self.handler.get_or_create_user(self.requester, "b", "display_name"),
            ResourceLimitError,
        )

    def test_register_mau_blocked(self):
        self.hs.config.limit_usage_by_mau = True
        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(self.lots_of_users)
        )
        self.get_failure(
            self.handler.register(localpart="local_part"), ResourceLimitError
        )

        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(self.hs.config.max_mau_value)
        )
        self.get_failure(
            self.handler.register(localpart="local_part"), ResourceLimitError
        )

    def test_auto_create_auto_join_rooms(self):
        room_alias_str = "#room:test"
        self.hs.config.auto_join_rooms = [room_alias_str]
        res = self.get_success(self.handler.register(localpart="jeff"))
        rooms = self.get_success(self.store.get_rooms_for_user(res[0]))
        directory_handler = self.hs.get_handlers().directory_handler
        room_alias = RoomAlias.from_string(room_alias_str)
        room_id = self.get_success(directory_handler.get_association(room_alias))

        self.assertTrue(room_id["room_id"] in rooms)
        self.assertEqual(len(rooms), 1)

    def test_auto_create_auto_join_rooms_with_no_rooms(self):
        self.hs.config.auto_join_rooms = []
        frank = UserID.from_string("@frank:test")
        res = self.get_success(self.handler.register(frank.localpart))
        self.assertEqual(res[0], frank.to_string())
        rooms = self.get_success(self.store.get_rooms_for_user(res[0]))
        self.assertEqual(len(rooms), 0)

    def test_auto_create_auto_join_where_room_is_another_domain(self):
        self.hs.config.auto_join_rooms = ["#room:another"]
        frank = UserID.from_string("@frank:test")
        res = self.get_success(self.handler.register(frank.localpart))
        self.assertEqual(res[0], frank.to_string())
        rooms = self.get_success(self.store.get_rooms_for_user(res[0]))
        self.assertEqual(len(rooms), 0)

    def test_auto_create_auto_join_where_auto_create_is_false(self):
        self.hs.config.autocreate_auto_join_rooms = False
        room_alias_str = "#room:test"
        self.hs.config.auto_join_rooms = [room_alias_str]
        res = self.get_success(self.handler.register(localpart="jeff"))
        rooms = self.get_success(self.store.get_rooms_for_user(res[0]))
        self.assertEqual(len(rooms), 0)

    def test_auto_create_auto_join_rooms_when_support_user_exists(self):
        room_alias_str = "#room:test"
        self.hs.config.auto_join_rooms = [room_alias_str]

        self.store.is_support_user = Mock(return_value=True)
        res = self.get_success(self.handler.register(localpart="support"))
        rooms = self.get_success(self.store.get_rooms_for_user(res[0]))
        self.assertEqual(len(rooms), 0)
        directory_handler = self.hs.get_handlers().directory_handler
        room_alias = RoomAlias.from_string(room_alias_str)
        self.get_failure(directory_handler.get_association(room_alias), SynapseError)

    def test_auto_create_auto_join_where_no_consent(self):
        """Test to ensure that the first user is not auto-joined to a room if
        they have not given general consent.
        """

        # Given:-
        #    * a user must give consent,
        #    * they have not given that consent
        #    * The server is configured to auto-join to a room
        # (and autocreate if necessary)

        event_creation_handler = self.hs.get_event_creation_handler()
        # (Messing with the internals of event_creation_handler is fragile
        # but can't see a better way to do this. One option could be to subclass
        # the test with custom config.)
        event_creation_handler._block_events_without_consent_error = "Error"
        event_creation_handler._consent_uri_builder = Mock()
        room_alias_str = "#room:test"
        self.hs.config.auto_join_rooms = [room_alias_str]

        # When:-
        #   * the user is registered and post consent actions are called
        res = self.get_success(self.handler.register(localpart="jeff"))
        self.get_success(self.handler.post_consent_actions(res[0]))

        # Then:-
        #   * Ensure that they have not been joined to the room
        rooms = self.get_success(self.store.get_rooms_for_user(res[0]))
        self.assertEqual(len(rooms), 0)

    def test_register_support_user(self):
        res = self.get_success(
            self.handler.register(localpart="user", user_type=UserTypes.SUPPORT)
        )
        self.assertTrue(self.store.is_support_user(res[0]))

    def test_register_not_support_user(self):
        res = self.get_success(self.handler.register(localpart="user"))
        self.assertFalse(self.store.is_support_user(res[0]))

    def test_invalid_user_id_length(self):
        invalid_user_id = "x" * 256
        self.get_failure(self.handler.register(localpart=invalid_user_id), SynapseError)
