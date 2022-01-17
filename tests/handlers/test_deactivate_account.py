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
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import AccountDataTypes
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
        super(DeactivateAccountTestCase, self).prepare(reactor, clock, hs)
        self._store = hs.get_datastore()

        self.user = self.register_user("user", "pass")
        self.token = self.login("user", "pass")

    def test_account_data_deleted_upon_deactivation(self) -> None:
        """
        Tests that account data is removed upon deactivation.
        """
        # Add some account data
        self.get_success(
            self._store.add_account_data_for_user(
                self.user,
                AccountDataTypes.DIRECT,
                {"@someone:remote": ["!somewhere:remote"]},
            )
        )

        # Request the deactivation of our account
        req = self.get_success(
            self.make_request(
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
        )
        self.assertEqual(req.code, 200, req)

        # Check that the account data does not persist.
        self.assertIsNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    AccountDataTypes.DIRECT,
                    self.user,
                )
            ),
        )

    def _rerun_retroactive_account_data_deletion_job(self) -> None:
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

    def test_account_data_deleted_retroactively_by_background_job_if_deactivated(
        self,
    ) -> None:
        """
        Tests that a user, who deactivated their account before account data was
        deleted automatically upon deactivation, has their account data retroactively
        scrubbed by the background job.
        """

        # Request the deactivation of our account
        req = self.get_success(
            self.make_request(
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
        )
        self.assertEqual(req.code, 200, req)

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
                    AccountDataTypes.DIRECT,
                    self.user,
                )
            ),
        )

        # Re-run the retroactive deletion job
        self._rerun_retroactive_account_data_deletion_job()

        # Check that the account data was cleared.
        self._store.get_global_account_data_by_type_for_user.invalidate_all()
        self.assertIsNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    AccountDataTypes.DIRECT,
                    self.user,
                )
            ),
        )

    def test_account_data_preserved_by_background_job_if_not_deactivated(self) -> None:
        """
        Tests that the background job does not scrub account data for users that have
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
                    AccountDataTypes.DIRECT,
                    self.user,
                )
            ),
        )

        # Re-run the retroactive deletion job
        self._rerun_retroactive_account_data_deletion_job()

        # Check that the account data was NOT cleared.
        self._store.get_global_account_data_by_type_for_user.invalidate_all()
        self.assertIsNotNone(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    AccountDataTypes.DIRECT,
                    self.user,
                )
            ),
        )
