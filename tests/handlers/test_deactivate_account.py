# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import Any, Dict

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import AccountDataTypes
from synapse.push.rulekinds import PRIORITY_CLASS_MAP
from synapse.rest import admin
from synapse.rest.client import account, login
from synapse.server import HomeServer
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class DeactivateAccountTestCase(HomeserverTestCase):
    servlets = [
        login.register_servlets,
        admin.register_servlets,
        account.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self._store = hs.get_datastores().main

        self.user = self.register_user("user", "pass")
        self.token = self.login("user", "pass")

    def _deactivate_my_account(self) -> None:
        """
        Deactivates the account `self.user` using `self.token` and asserts
        that it returns a 200 success code.
        """
        req = self.make_request(
            "POST",
            "account/deactivate",
            {
                "auth": {
                    "type": "m.login.password",
                    "user": self.user,
                    "password": "pass",
                },
                "erase": True,
            },
            access_token=self.token,
        )

        self.assertEqual(req.code, HTTPStatus.OK, req)

    def test_global_account_data_deleted_upon_deactivation(self) -> None:
        """
        Tests that global account data is removed upon deactivation.
        """
        # Add some account data
        self.get_success(
            self._store.add_account_data_for_user(
                self.user,
                AccountDataTypes.DIRECT,
                {"@someone:remote": ["!somewhere:remote"]},
            )
        )

        # Check that we actually added some.
        self.assertIsNotNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    self.user, AccountDataTypes.DIRECT
                )
            ),
        )

        # Request the deactivation of our account
        self._deactivate_my_account()

        # Check that the account data does not persist.
        self.assertIsNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    self.user, AccountDataTypes.DIRECT
                )
            ),
        )

    def test_room_account_data_deleted_upon_deactivation(self) -> None:
        """
        Tests that room account data is removed upon deactivation.
        """
        room_id = "!room:test"

        # Add some room account data
        self.get_success(
            self._store.add_account_data_to_room(
                self.user,
                room_id,
                "m.fully_read",
                {"event_id": "$aaaa:test"},
            )
        )

        # Check that we actually added some.
        self.assertIsNotNone(
            self.get_success(
                self._store.get_account_data_for_room_and_type(
                    self.user, room_id, "m.fully_read"
                )
            ),
        )

        # Request the deactivation of our account
        self._deactivate_my_account()

        # Check that the account data does not persist.
        self.assertIsNone(
            self.get_success(
                self._store.get_account_data_for_room_and_type(
                    self.user, room_id, "m.fully_read"
                )
            ),
        )

    def _is_custom_rule(self, push_rule: Dict[str, Any]) -> bool:
        """
        Default rules start with a dot: such as .m.rule and .im.vector.
        This function returns true iff a rule is custom (not default).
        """
        return "/." not in push_rule["rule_id"]

    def test_push_rules_deleted_upon_account_deactivation(self) -> None:
        """
        Push rules are a special case of account data.
        They are stored separately but get sent to the client as account data in /sync.
        This tests that deactivating a user deletes push rules along with the rest
        of their account data.
        """

        # Add a push rule
        self.get_success(
            self._store.add_push_rule(
                self.user,
                "personal.override.rule1",
                PRIORITY_CLASS_MAP["override"],
                [],
                [],
            )
        )

        # Test the rule exists
        push_rules = self.get_success(self._store.get_push_rules_for_user(self.user))
        # Filter out default rules; we don't care
        push_rules = list(filter(self._is_custom_rule, push_rules))
        # Check our rule made it
        self.assertEqual(
            push_rules,
            [
                {
                    "user_name": "@user:test",
                    "rule_id": "personal.override.rule1",
                    "priority_class": 5,
                    "priority": 0,
                    "conditions": [],
                    "actions": [],
                    "default": False,
                }
            ],
            push_rules,
        )

        # Request the deactivation of our account
        self._deactivate_my_account()

        push_rules = self.get_success(self._store.get_push_rules_for_user(self.user))
        # Filter out default rules; we don't care
        push_rules = list(filter(self._is_custom_rule, push_rules))
        # Check our rule no longer exists
        self.assertEqual(push_rules, [], push_rules)

    def test_ignored_users_deleted_upon_deactivation(self) -> None:
        """
        Ignored users are a special case of account data.
        They get denormalised into the `ignored_users` table upon being stored as
        account data.
        Test that a user's list of ignored users is deleted upon deactivation.
        """

        # Add an ignored user
        self.get_success(
            self._store.add_account_data_for_user(
                self.user,
                AccountDataTypes.IGNORED_USER_LIST,
                {"ignored_users": {"@sheltie:test": {}}},
            )
        )

        # Test the user is ignored
        self.assertEqual(
            self.get_success(self._store.ignored_by("@sheltie:test")), {self.user}
        )

        # Request the deactivation of our account
        self._deactivate_my_account()

        # Test the user is no longer ignored by the user that was deactivated
        self.assertEqual(
            self.get_success(self._store.ignored_by("@sheltie:test")), set()
        )

    def _rerun_retroactive_account_data_deletion_update(self) -> None:
        # Reset the 'all done' flag
        self._store.db_pool.updates._all_done = False

        self.get_success(
            self._store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": "delete_account_data_for_deactivated_users",
                    "progress_json": "{}",
                },
            )
        )

        self.wait_for_background_updates()

    def test_account_data_deleted_retroactively_by_background_update_if_deactivated(
        self,
    ) -> None:
        """
        Tests that a user, who deactivated their account before account data was
        deleted automatically upon deactivation, has their account data retroactively
        scrubbed by the background update.
        """

        # Request the deactivation of our account
        self._deactivate_my_account()

        # Add some account data
        # (we do this after the deactivation so that the act of deactivating doesn't
        # clear it out. This emulates a user that was deactivated before this was cleared
        # upon deactivation.)
        self.get_success(
            self._store.add_account_data_for_user(
                self.user,
                AccountDataTypes.DIRECT,
                {"@someone:remote": ["!somewhere:remote"]},
            )
        )

        # Check that the account data is there.
        self.assertIsNotNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    self.user,
                    AccountDataTypes.DIRECT,
                )
            ),
        )

        # Re-run the retroactive deletion update
        self._rerun_retroactive_account_data_deletion_update()

        # Check that the account data was cleared.
        self.assertIsNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    self.user,
                    AccountDataTypes.DIRECT,
                )
            ),
        )

    def test_account_data_preserved_by_background_update_if_not_deactivated(
        self,
    ) -> None:
        """
        Tests that the background update does not scrub account data for users that have
        not been deactivated.
        """

        # Add some account data
        # (we do this after the deactivation so that the act of deactivating doesn't
        # clear it out. This emulates a user that was deactivated before this was cleared
        # upon deactivation.)
        self.get_success(
            self._store.add_account_data_for_user(
                self.user,
                AccountDataTypes.DIRECT,
                {"@someone:remote": ["!somewhere:remote"]},
            )
        )

        # Check that the account data is there.
        self.assertIsNotNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    self.user,
                    AccountDataTypes.DIRECT,
                )
            ),
        )

        # Re-run the retroactive deletion update
        self._rerun_retroactive_account_data_deletion_update()

        # Check that the account data was NOT cleared.
        self.assertIsNotNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    self.user,
                    AccountDataTypes.DIRECT,
                )
            ),
        )
